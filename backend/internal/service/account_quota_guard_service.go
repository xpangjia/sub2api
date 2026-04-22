package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// quota_guard 在 Account.Extra 中使用的 JSON key。
// 这些 key 独立于 temp_unschedulable_reason 等已有字段，避免与过期/限流机制混淆。
const (
	quotaGuardPausedReasonKey = "quota_guard_paused_reason" // string，非空表示当前因配额被自动暂停；值为触发维度（如 "5h" / "G3P"）
	quotaGuardPausedAtKey     = "quota_guard_paused_at"     // RFC3339 时间戳，仅排障用
	quotaGuardSuppressedKey   = "quota_guard_suppressed"    // bool，管理员手动解除后写 true，守护跳过该账号直至窗口 reset
)

// AccountUsageReader 抽象 usage 查询行为，便于测试与解耦。
// 真实实现为 *AccountUsageService。
type AccountUsageReader interface {
	GetUsage(ctx context.Context, accountID int64) (*UsageInfo, error)
	GetPassiveUsage(ctx context.Context, accountID int64) (*UsageInfo, error)
}

// AccountQuotaGuardService 周期扫描 Antigravity 与 Anthropic OAuth 账号，
// 若任一用量维度触达阈值则自动暂停；恢复与手动豁免逻辑见方法注释。
//
// 数据源：
//   - Anthropic OAuth / Setup Token：GetPassiveUsage（纯读 extra，零上游调用）
//   - Antigravity：GetUsage（内置 3min 内存缓存，真正打上游频率远低于扫描频率）
//
// 与其他暂停机制的关系：
//   - 仅操作 `status=active` 的账号，被封/过期等由它处职责处理
//   - 不动 temp_unschedulable_* / rate_limit / overload 字段，仅读/写 extra 里约定的 quota_guard_* key
type AccountQuotaGuardService struct {
	accountRepo  AccountRepository
	usageReader  AccountUsageReader
	threshold    float64       // 触发暂停的利用率，0-1（如 0.90 表示 90%）
	resumeBelow  float64       // 自动恢复的下降阈值，== threshold（同一个值进/出）
	suppressExit float64       // 手动豁免自动清除的下降阈值，默认 threshold 的 0.55（即 <50%）
	interval     time.Duration // tick 周期
	enabled      bool

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewAccountQuotaGuardService 构造实例。threshold 传 0-1 的比例（如 0.9）。
// interval <= 0 或 enabled=false 时 Start 直接返回、不启动 goroutine。
func NewAccountQuotaGuardService(
	accountRepo AccountRepository,
	usageReader AccountUsageReader,
	enabled bool,
	threshold float64,
	interval time.Duration,
) *AccountQuotaGuardService {
	if threshold <= 0 || threshold > 1 {
		threshold = 0.9
	}
	return &AccountQuotaGuardService{
		accountRepo:  accountRepo,
		usageReader:  usageReader,
		threshold:    threshold,
		resumeBelow:  threshold,
		suppressExit: threshold * 0.55,
		interval:     interval,
		enabled:      enabled,
		stopCh:       make(chan struct{}),
	}
}

// Start 启动后台周期扫描。幂等（多次调用无副作用，但只有首次会起 goroutine）。
func (s *AccountQuotaGuardService) Start() {
	if s == nil || !s.enabled || s.interval <= 0 || s.accountRepo == nil || s.usageReader == nil {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		// 首次启动延迟 5s，让依赖服务（缓存/token refresh）先就位。
		select {
		case <-time.After(5 * time.Second):
		case <-s.stopCh:
			return
		}
		s.runOnce()

		for {
			select {
			case <-ticker.C:
				s.runOnce()
			case <-s.stopCh:
				return
			}
		}
	}()
}

// Stop 通知后台循环退出并等待结束。
func (s *AccountQuotaGuardService) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.wg.Wait()
}

// runOnce 执行一次完整扫描。错误只记录日志，不中断循环。
// - list 用 10s 超时（本地查询）
// - 每个账号的 usage 查询独立使用 15s 超时，避免慢账号拖垮整轮扫描
func (s *AccountQuotaGuardService) runOnce() {
	start := time.Now()
	scanned := 0
	paused := 0
	resumed := 0
	suppressCleared := 0
	defer func() {
		slog.Info("quota_guard.tick",
			"scanned", scanned, "paused", paused, "resumed", resumed,
			"suppress_cleared", suppressCleared, "duration_ms", time.Since(start).Milliseconds())
	}()

	platforms := []string{PlatformAntigravity, PlatformAnthropic}
	for _, platform := range platforms {
		listCtx, listCancel := context.WithTimeout(context.Background(), 10*time.Second)
		accounts, err := s.accountRepo.ListByPlatform(listCtx, platform)
		listCancel()
		if err != nil {
			slog.Warn("quota_guard.list_failed", "platform", platform, "error", err)
			continue
		}
		for i := range accounts {
			acc := &accounts[i]
			if !s.shouldInspect(acc) {
				continue
			}
			scanned++
			inspectCtx, inspectCancel := context.WithTimeout(context.Background(), 15*time.Second)
			action := s.inspectOne(inspectCtx, acc, time.Now())
			inspectCancel()
			switch action {
			case "paused":
				paused++
			case "resumed":
				resumed++
			case "suppress_cleared":
				suppressCleared++
			}
		}
	}
}

// shouldInspect 决定该账号是否纳入本轮扫描。
// 放过：非 active、非 OAuth、被封/需验证、临时不可调度中、已过期等。
func (s *AccountQuotaGuardService) shouldInspect(acc *Account) bool {
	if acc == nil || !acc.IsActive() {
		return false
	}
	// 仅 OAuth 形态。Anthropic APIKey / Antigravity APIKey 不走本机制（没有窗口配额概念）。
	if acc.Type != AccountTypeOAuth && acc.Type != AccountTypeSetupToken {
		return false
	}
	// 过期账号交给 AccountExpiryService。
	if acc.ExpiresAt != nil && acc.AutoPauseOnExpired && !time.Now().Before(*acc.ExpiresAt) {
		return false
	}
	return true
}

// inspectOne 判定单个账号当前处于「暂停 / 恢复 / 豁免清除 / 首次触发」哪种状态并执行相应动作。
// 返回本次的动作标签（"paused"/"resumed"/"suppress_cleared"/""），供 runOnce 计数。
func (s *AccountQuotaGuardService) inspectOne(ctx context.Context, acc *Account, now time.Time) string {
	usage, err := s.fetchUsage(ctx, acc)
	if err != nil {
		slog.Debug("quota_guard.usage_failed", "account_id", acc.ID, "platform", acc.Platform, "error", err)
		return ""
	}
	if usage == nil {
		usage = &UsageInfo{}
	}

	// 合并两个数据源：
	//   - usage.* 各 bucket（Antigravity 配额 / Anthropic 5h 7d 窗口）
	//   - account.extra.model_rate_limits 中未到期的条目（视为该 model 维度 100%）
	maxBucket, maxUtil := maxUtilizationAcrossBuckets(usage)
	if rlBucket, rlUtil := maxRateLimitFromExtra(acc.Extra, now); rlUtil > maxUtil {
		maxBucket, maxUtil = rlBucket, rlUtil
	}

	pausedReason := strExtra(acc.Extra, quotaGuardPausedReasonKey)
	suppressed := boolExtra(acc.Extra, quotaGuardSuppressedKey)

	switch {
	case suppressed:
		// 手动豁免中：usage 显著回落则自动清除豁免，下一轮恢复正常监管。
		if maxUtil < s.suppressExit {
			updates := map[string]any{
				quotaGuardSuppressedKey: false,
			}
			if err := s.accountRepo.UpdateExtra(ctx, acc.ID, updates); err != nil {
				slog.Warn("quota_guard.clear_suppress_failed", "account_id", acc.ID, "error", err)
				return ""
			}
			slog.Info("quota_guard.suppress_cleared",
				"account_id", acc.ID, "platform", acc.Platform, "max_util", maxUtil)
			return "suppress_cleared"
		}
		return ""

	case pausedReason != "":
		// 本服务已暂停过：usage 回落到阈值以下则自动恢复。
		if maxUtil < s.resumeBelow {
			if err := s.accountRepo.SetSchedulable(ctx, acc.ID, true); err != nil {
				slog.Warn("quota_guard.resume_failed", "account_id", acc.ID, "error", err)
				return ""
			}
			if err := s.accountRepo.UpdateExtra(ctx, acc.ID, map[string]any{
				quotaGuardPausedReasonKey: "",
				quotaGuardPausedAtKey:     "",
			}); err != nil {
				slog.Warn("quota_guard.clear_reason_failed", "account_id", acc.ID, "error", err)
			}
			slog.Info("quota_guard.resumed",
				"account_id", acc.ID, "platform", acc.Platform,
				"prev_reason", pausedReason, "max_util", maxUtil)
			return "resumed"
		}
		return ""

	default:
		if maxUtil < s.threshold {
			return ""
		}
		if acc.Schedulable {
			// 首次触发：停调度 + 打 reason。
			if err := s.accountRepo.SetSchedulable(ctx, acc.ID, false); err != nil {
				slog.Warn("quota_guard.pause_failed", "account_id", acc.ID, "error", err)
				return ""
			}
			if err := s.accountRepo.UpdateExtra(ctx, acc.ID, map[string]any{
				quotaGuardPausedReasonKey: maxBucket,
				quotaGuardPausedAtKey:     now.UTC().Format(time.RFC3339),
			}); err != nil {
				slog.Warn("quota_guard.mark_reason_failed", "account_id", acc.ID, "error", err)
			}
			slog.Info("quota_guard.paused",
				"account_id", acc.ID, "platform", acc.Platform,
				"reason", maxBucket, "max_util", maxUtil, "threshold", s.threshold)
			return "paused"
		}
		// 账号已是 schedulable=false（别的子系统写的）且触达阈值：
		// 不再碰 schedulable，只补打 reason 徽章，方便管理员在 UI 上看到"配额耗尽"归因。
		if err := s.accountRepo.UpdateExtra(ctx, acc.ID, map[string]any{
			quotaGuardPausedReasonKey: maxBucket,
			quotaGuardPausedAtKey:     now.UTC().Format(time.RFC3339),
		}); err != nil {
			slog.Warn("quota_guard.annotate_failed", "account_id", acc.ID, "error", err)
			return ""
		}
		slog.Info("quota_guard.annotated",
			"account_id", acc.ID, "platform", acc.Platform,
			"reason", maxBucket, "max_util", maxUtil)
		return "paused"
	}
}

// fetchUsage 按 platform 分流到 passive / active 读取路径。
func (s *AccountQuotaGuardService) fetchUsage(ctx context.Context, acc *Account) (*UsageInfo, error) {
	switch acc.Platform {
	case PlatformAnthropic:
		return s.usageReader.GetPassiveUsage(ctx, acc.ID)
	case PlatformAntigravity:
		return s.usageReader.GetUsage(ctx, acc.ID)
	default:
		return nil, fmt.Errorf("unsupported platform %q", acc.Platform)
	}
}

// maxUtilizationAcrossBuckets 返回在所有纳管维度中的最大 utilization（0-1）与来源 bucket 名。
// bucket 名用于写入 extra 供排障（例如 "5h"、"7d"、"7d_sonnet"、"G3P"）。
func maxUtilizationAcrossBuckets(usage *UsageInfo) (string, float64) {
	if usage == nil {
		return "", 0
	}
	max := 0.0
	name := ""

	consider := func(bucket string, utilPercent float64) {
		// utilization 在 UsageProgress 里是 0-100 口径，在 AntigravityModelQuota 里是 0-100 int；
		// 统一归一到 0-1 再比较。
		v := utilPercent / 100.0
		if v > max {
			max = v
			name = bucket
		}
	}

	if usage.FiveHour != nil {
		consider("5h", usage.FiveHour.Utilization)
	}
	if usage.SevenDay != nil {
		consider("7d", usage.SevenDay.Utilization)
	}
	if usage.SevenDaySonnet != nil {
		consider("7d_sonnet", usage.SevenDaySonnet.Utilization)
	}
	for bucketKey, q := range usage.AntigravityQuota {
		if q == nil {
			continue
		}
		consider(normalizeAntigravityBucketName(bucketKey), float64(q.Utilization))
	}
	return name, max
}

// maxRateLimitFromExtra 扫描 account.extra.model_rate_limits，
// 任一未到期的 model 条目视为该维度 100%（上游正在限流 = 用量已触顶）。
// 返回命中 bucket 名（以 model 名为 bucket，前端徽章直接能看懂）与归一化利用率 0-1。
// 无命中返回 ("", 0)。
func maxRateLimitFromExtra(extra map[string]any, now time.Time) (string, float64) {
	if len(extra) == 0 {
		return "", 0
	}
	raw, ok := extra["model_rate_limits"].(map[string]any)
	if !ok || len(raw) == 0 {
		return "", 0
	}
	best := ""
	for model, v := range raw {
		entry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		resetRaw, ok := entry["rate_limit_reset_at"].(string)
		if !ok || resetRaw == "" {
			continue
		}
		resetAt, err := time.Parse(time.RFC3339, resetRaw)
		if err != nil {
			continue
		}
		if resetAt.After(now) {
			best = model
			break
		}
	}
	if best == "" {
		return "", 0
	}
	return best, 1.0
}

// normalizeAntigravityBucketName 缩短 antigravity quota key，避免在 extra 里存过长字符串。
// 未识别的保持原样。
func normalizeAntigravityBucketName(raw string) string {
	return strings.TrimSpace(raw)
}

// 小工具：从 Extra map 安全取 string / bool，避免重复 type assert。
func strExtra(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func boolExtra(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true")
	}
	return false
}

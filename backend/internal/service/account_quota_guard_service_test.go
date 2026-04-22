//go:build unit

package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

// quotaGuardRepoStub 嵌入现有 mockAccountRepoForPlatform 复用 stub 方法，
// 只覆盖本测试需要观察或控制的几条路径。
type quotaGuardRepoStub struct {
	mockAccountRepoForPlatform

	listByPlatformFunc func(ctx context.Context, platform string) ([]Account, error)

	setSchedulableCalls []struct {
		id          int64
		schedulable bool
	}
	updateExtraCalls []struct {
		id      int64
		updates map[string]any
	}

	setSchedulableErr error
	updateExtraErr    error
}

func (m *quotaGuardRepoStub) ListByPlatform(ctx context.Context, platform string) ([]Account, error) {
	if m.listByPlatformFunc != nil {
		return m.listByPlatformFunc(ctx, platform)
	}
	var result []Account
	for _, acc := range m.accounts {
		if acc.Platform == platform {
			result = append(result, acc)
		}
	}
	return result, nil
}

func (m *quotaGuardRepoStub) SetSchedulable(ctx context.Context, id int64, schedulable bool) error {
	m.setSchedulableCalls = append(m.setSchedulableCalls, struct {
		id          int64
		schedulable bool
	}{id, schedulable})
	if acc, ok := m.accountsByID[id]; ok {
		acc.Schedulable = schedulable
	}
	return m.setSchedulableErr
}

func (m *quotaGuardRepoStub) UpdateExtra(ctx context.Context, id int64, updates map[string]any) error {
	m.updateExtraCalls = append(m.updateExtraCalls, struct {
		id      int64
		updates map[string]any
	}{id, updates})
	if acc, ok := m.accountsByID[id]; ok {
		if acc.Extra == nil {
			acc.Extra = map[string]any{}
		}
		for k, v := range updates {
			acc.Extra[k] = v
		}
	}
	return m.updateExtraErr
}

// quotaGuardUsageStub 用于模拟 AccountUsageReader 的返回值。
// 按 accountID 分别返回，路径选择（active/passive）无关紧要，测试仅关心数值。
type quotaGuardUsageStub struct {
	byAccountID map[int64]*UsageInfo
	err         error
}

func (m *quotaGuardUsageStub) GetUsage(ctx context.Context, accountID int64) (*UsageInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.byAccountID[accountID], nil
}

func (m *quotaGuardUsageStub) GetPassiveUsage(ctx context.Context, accountID int64) (*UsageInfo, error) {
	return m.GetUsage(ctx, accountID)
}

func makeOAuthAccount(id int64, platform string, schedulable bool, extra map[string]any) Account {
	if extra == nil {
		extra = map[string]any{}
	}
	return Account{
		ID:          id,
		Platform:    platform,
		Type:        AccountTypeOAuth,
		Status:      StatusActive,
		Schedulable: schedulable,
		Extra:       extra,
	}
}

func newQuotaGuardTestRepo(accounts ...Account) *quotaGuardRepoStub {
	stub := &quotaGuardRepoStub{}
	stub.accounts = accounts
	stub.accountsByID = make(map[int64]*Account, len(accounts))
	for i := range stub.accounts {
		stub.accountsByID[stub.accounts[i].ID] = &stub.accounts[i]
	}
	return stub
}

func TestQuotaGuard_PausesAccountAtThreshold(t *testing.T) {
	repo := newQuotaGuardTestRepo(
		makeOAuthAccount(1, PlatformAnthropic, true, nil),
	)
	usage := &quotaGuardUsageStub{
		byAccountID: map[int64]*UsageInfo{
			1: {FiveHour: &UsageProgress{Utilization: 92}},
		},
	}
	svc := NewAccountQuotaGuardService(repo, usage, true, 0.9, time.Minute)
	svc.runOnce()

	if len(repo.setSchedulableCalls) != 1 {
		t.Fatalf("expected 1 SetSchedulable call, got %d", len(repo.setSchedulableCalls))
	}
	if repo.setSchedulableCalls[0].schedulable {
		t.Fatalf("expected schedulable=false, got true")
	}
	if reason, _ := repo.accountsByID[1].Extra[quotaGuardPausedReasonKey].(string); reason != "5h" {
		t.Fatalf("expected paused_reason=5h, got %q", reason)
	}
	if _, ok := repo.accountsByID[1].Extra[quotaGuardPausedAtKey]; !ok {
		t.Fatalf("expected paused_at to be set")
	}
}

func TestQuotaGuard_DoesNotPauseBelowThreshold(t *testing.T) {
	repo := newQuotaGuardTestRepo(
		makeOAuthAccount(1, PlatformAnthropic, true, nil),
	)
	usage := &quotaGuardUsageStub{
		byAccountID: map[int64]*UsageInfo{
			1: {FiveHour: &UsageProgress{Utilization: 89.9}},
		},
	}
	svc := NewAccountQuotaGuardService(repo, usage, true, 0.9, time.Minute)
	svc.runOnce()

	if len(repo.setSchedulableCalls) != 0 {
		t.Fatalf("expected no SetSchedulable calls, got %d", len(repo.setSchedulableCalls))
	}
}

func TestQuotaGuard_AutoResumesWhenUsageDrops(t *testing.T) {
	extra := map[string]any{
		quotaGuardPausedReasonKey: "7d",
		quotaGuardPausedAtKey:     time.Now().Format(time.RFC3339),
	}
	acc := makeOAuthAccount(1, PlatformAnthropic, false, extra)
	repo := newQuotaGuardTestRepo(acc)
	usage := &quotaGuardUsageStub{
		byAccountID: map[int64]*UsageInfo{
			1: {
				FiveHour: &UsageProgress{Utilization: 40},
				SevenDay: &UsageProgress{Utilization: 20},
			},
		},
	}
	svc := NewAccountQuotaGuardService(repo, usage, true, 0.9, time.Minute)
	svc.runOnce()

	if len(repo.setSchedulableCalls) != 1 || !repo.setSchedulableCalls[0].schedulable {
		t.Fatalf("expected SetSchedulable(true) once, got %+v", repo.setSchedulableCalls)
	}
	reason, _ := repo.accountsByID[1].Extra[quotaGuardPausedReasonKey].(string)
	if reason != "" {
		t.Fatalf("expected paused_reason to be cleared, got %q", reason)
	}
}

func TestQuotaGuard_SuppressedAccountSkippedThenClearedWhenUsageLow(t *testing.T) {
	// 场景 1：suppressed + 高用量 → 什么都不动
	extra := map[string]any{quotaGuardSuppressedKey: true}
	repo := newQuotaGuardTestRepo(makeOAuthAccount(1, PlatformAnthropic, true, extra))
	usage := &quotaGuardUsageStub{
		byAccountID: map[int64]*UsageInfo{
			1: {FiveHour: &UsageProgress{Utilization: 95}},
		},
	}
	svc := NewAccountQuotaGuardService(repo, usage, true, 0.9, time.Minute)
	svc.runOnce()

	if len(repo.setSchedulableCalls) != 0 {
		t.Fatalf("suppressed account must not be paused, got %+v", repo.setSchedulableCalls)
	}
	if len(repo.updateExtraCalls) != 0 {
		t.Fatalf("suppressed account should not have extra cleared when usage high, got %+v", repo.updateExtraCalls)
	}

	// 场景 2：suppressed + 低用量 → 自动清除豁免
	repo2 := newQuotaGuardTestRepo(makeOAuthAccount(2, PlatformAnthropic, true, map[string]any{quotaGuardSuppressedKey: true}))
	usage2 := &quotaGuardUsageStub{
		byAccountID: map[int64]*UsageInfo{
			2: {FiveHour: &UsageProgress{Utilization: 10}},
		},
	}
	svc2 := NewAccountQuotaGuardService(repo2, usage2, true, 0.9, time.Minute)
	svc2.runOnce()

	if len(repo2.updateExtraCalls) != 1 {
		t.Fatalf("expected 1 UpdateExtra call to clear suppress, got %d", len(repo2.updateExtraCalls))
	}
	if v, _ := repo2.accountsByID[2].Extra[quotaGuardSuppressedKey].(bool); v {
		t.Fatalf("expected suppressed cleared to false, still true")
	}
}

func TestQuotaGuard_AntigravityMultiBucketUsesMaxBucket(t *testing.T) {
	repo := newQuotaGuardTestRepo(
		makeOAuthAccount(1, PlatformAntigravity, true, nil),
	)
	usage := &quotaGuardUsageStub{
		byAccountID: map[int64]*UsageInfo{
			1: {
				AntigravityQuota: map[string]*AntigravityModelQuota{
					"Claude": {Utilization: 85},
					"G3P":    {Utilization: 95},
					"G3F":    {Utilization: 10},
				},
			},
		},
	}
	svc := NewAccountQuotaGuardService(repo, usage, true, 0.9, time.Minute)
	svc.runOnce()

	if len(repo.setSchedulableCalls) != 1 || repo.setSchedulableCalls[0].schedulable {
		t.Fatalf("expected pause, got %+v", repo.setSchedulableCalls)
	}
	reason, _ := repo.accountsByID[1].Extra[quotaGuardPausedReasonKey].(string)
	if reason != "G3P" {
		t.Fatalf("expected reason=G3P (max bucket), got %q", reason)
	}
}

func TestQuotaGuard_SkipsNonOAuthAccountsAndNonActive(t *testing.T) {
	accounts := []Account{
		{ID: 1, Platform: PlatformAnthropic, Type: AccountTypeAPIKey, Status: StatusActive, Schedulable: true},
		{ID: 2, Platform: PlatformAnthropic, Type: AccountTypeOAuth, Status: "disabled", Schedulable: true},
	}
	repo := newQuotaGuardTestRepo(accounts...)
	usage := &quotaGuardUsageStub{
		byAccountID: map[int64]*UsageInfo{
			1: {FiveHour: &UsageProgress{Utilization: 95}},
			2: {FiveHour: &UsageProgress{Utilization: 95}},
		},
	}
	svc := NewAccountQuotaGuardService(repo, usage, true, 0.9, time.Minute)
	svc.runOnce()

	if len(repo.setSchedulableCalls) != 0 {
		t.Fatalf("expected no pauses, got %+v", repo.setSchedulableCalls)
	}
}

func TestQuotaGuard_AnnotatesAlreadyUnschedulableAccount(t *testing.T) {
	// schedulable 已经是 false（可能由过期/限流等写的），守护不覆盖 schedulable，
	// 但会补打 quota_guard_paused_reason 以便 UI 显示归因。
	repo := newQuotaGuardTestRepo(
		makeOAuthAccount(1, PlatformAnthropic, false, nil),
	)
	usage := &quotaGuardUsageStub{
		byAccountID: map[int64]*UsageInfo{
			1: {FiveHour: &UsageProgress{Utilization: 95}},
		},
	}
	svc := NewAccountQuotaGuardService(repo, usage, true, 0.9, time.Minute)
	svc.runOnce()

	if len(repo.setSchedulableCalls) != 0 {
		t.Fatalf("must not touch schedulable, got %+v", repo.setSchedulableCalls)
	}
	if len(repo.updateExtraCalls) != 1 {
		t.Fatalf("expected 1 extra annotation, got %+v", repo.updateExtraCalls)
	}
	if r, _ := repo.accountsByID[1].Extra[quotaGuardPausedReasonKey].(string); r != "5h" {
		t.Fatalf("expected reason=5h, got %q", r)
	}
}

func TestQuotaGuard_ModelRateLimitsCountsAsFullyUsed(t *testing.T) {
	// model_rate_limits 里存在未到期的条目 → 视为该 model 维度 100%。
	extra := map[string]any{
		"model_rate_limits": map[string]any{
			"claude-opus-4-6-thinking": map[string]any{
				"rate_limited_at":     time.Now().Add(-time.Minute).Format(time.RFC3339),
				"rate_limit_reset_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			},
		},
	}
	repo := newQuotaGuardTestRepo(makeOAuthAccount(1, PlatformAntigravity, true, extra))
	usage := &quotaGuardUsageStub{
		byAccountID: map[int64]*UsageInfo{
			1: {AntigravityQuota: map[string]*AntigravityModelQuota{"Claude": {Utilization: 10}}},
		},
	}
	svc := NewAccountQuotaGuardService(repo, usage, true, 0.9, time.Minute)
	svc.runOnce()

	if len(repo.setSchedulableCalls) != 1 || repo.setSchedulableCalls[0].schedulable {
		t.Fatalf("expected pause on rate_limit entry, got %+v", repo.setSchedulableCalls)
	}
	if r, _ := repo.accountsByID[1].Extra[quotaGuardPausedReasonKey].(string); r != "claude-opus-4-6-thinking" {
		t.Fatalf("expected reason=model name, got %q", r)
	}
}

func TestQuotaGuard_ExpiredRateLimitsIgnored(t *testing.T) {
	extra := map[string]any{
		"model_rate_limits": map[string]any{
			"claude-sonnet-4-6": map[string]any{
				"rate_limit_reset_at": time.Now().Add(-time.Hour).Format(time.RFC3339),
			},
		},
	}
	repo := newQuotaGuardTestRepo(makeOAuthAccount(1, PlatformAntigravity, true, extra))
	usage := &quotaGuardUsageStub{byAccountID: map[int64]*UsageInfo{1: {}}}
	svc := NewAccountQuotaGuardService(repo, usage, true, 0.9, time.Minute)
	svc.runOnce()

	if len(repo.setSchedulableCalls) != 0 {
		t.Fatalf("expired entries must not trigger pause, got %+v", repo.setSchedulableCalls)
	}
}

func TestQuotaGuard_DisabledServiceIsNoop(t *testing.T) {
	repo := newQuotaGuardTestRepo(
		makeOAuthAccount(1, PlatformAnthropic, true, nil),
	)
	usage := &quotaGuardUsageStub{
		byAccountID: map[int64]*UsageInfo{
			1: {FiveHour: &UsageProgress{Utilization: 99}},
		},
	}
	svc := NewAccountQuotaGuardService(repo, usage, false, 0.9, time.Minute)
	// Start 直接返回；runOnce 可被直接调但这里测的是 Start 不起 goroutine。
	svc.Start()
	// 给潜在的 goroutine 一点时间（应该没有）
	time.Sleep(10 * time.Millisecond)
	svc.Stop()

	if len(repo.setSchedulableCalls) != 0 {
		t.Fatalf("disabled service must not run, got %+v", repo.setSchedulableCalls)
	}
}

func TestQuotaGuard_UsageErrorDoesNotAbortLoop(t *testing.T) {
	repo := newQuotaGuardTestRepo(
		makeOAuthAccount(1, PlatformAnthropic, true, nil),
		makeOAuthAccount(2, PlatformAnthropic, true, nil),
	)
	usage := &quotaGuardUsageStub{
		byAccountID: map[int64]*UsageInfo{
			2: {FiveHour: &UsageProgress{Utilization: 95}},
		},
		err: errors.New("boom"),
	}
	svc := NewAccountQuotaGuardService(repo, usage, true, 0.9, time.Minute)
	// 注入错误后每次 GetUsage 都返回 err；预期：无任何写入，不 panic
	svc.runOnce()

	if len(repo.setSchedulableCalls) != 0 {
		t.Fatalf("should not pause on error, got %+v", repo.setSchedulableCalls)
	}
}

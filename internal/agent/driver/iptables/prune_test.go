package iptables

import (
	"context"
	"testing"

	myfwv1 "iptables-tool/api/myfw/v1"
)

// TestApplyPrunesOrphanChains 验证删除实例后,其专属子链(MARKMANGLE/MARKACL-FWD)
// 不再被本轮 customChains 引用时,Apply 自动 -F + -X 清理,避免孤儿链残留。
// 系统链(managedChains)与本轮 customChains 保留。
func TestApplyPrunesOrphanChains(t *testing.T) {
	d, fake := newDriver(t)
	ctx := context.Background()

	// 第一次 Apply:含 MARKMANGLE + MARKACL-FWD 子链
	cc := []*myfwv1.CustomChainDef{
		{Name: "MARKMANGLE", Parent: "MYFW-MANGLE", Table: "mangle"},
		{Name: "MARKACL-FWD", Parent: "MYFW-FORWARD", Table: "filter"},
	}
	rules := []*myfwv1.CompiledRule{
		{Id: "m1", Chain: "MARKMANGLE", Action: myfwv1.Action_ACTION_MARK,
			Protocol: myfwv1.Protocol_PROTOCOL_TCP, PortRange: "8080", Mark: 15},
	}
	if _, err := d.Apply(ctx, &myfwv1.RuleSet{Rules: rules, CustomChains: cc}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if _, ok := fake.Tables["mangle"]["MYFW-MARKMANGLE"]; !ok {
		t.Fatal("第一次 Apply 后 MYFW-MARKMANGLE 应存在")
	}

	// 第二次 Apply:无 MARKMANGLE/MARKACL-FWD(实例已删),应被清理
	if _, err := d.Apply(ctx, &myfwv1.RuleSet{}); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if _, ok := fake.Tables["mangle"]["MYFW-MARKMANGLE"]; ok {
		t.Fatal("MYFW-MARKMANGLE 应被清理(孤儿链)")
	}
	if _, ok := fake.Tables["filter"]["MYFW-MARKACL-FWD"]; ok {
		t.Fatal("MYFW-MARKACL-FWD 应被清理(孤儿链)")
	}
	// 系统链保留
	if _, ok := fake.Tables["filter"]["MYFW-INPUT"]; !ok {
		t.Fatal("系统链 MYFW-INPUT 应保留")
	}
	if _, ok := fake.Tables["filter"]["MYFW-FORWARD"]; !ok {
		t.Fatal("系统链 MYFW-FORWARD 应保留")
	}
}

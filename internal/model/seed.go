package model

import "gorm.io/gorm"

// 常用策略组(自定义子链)预设:覆盖主机入站/容器转发/打标/NAT 常见场景,
// 仅首次启动播种(一次性种子标记 seed.custom_chains.v1),用户删除/编辑后
// 重启不会重建或覆盖,与用户自建链同等对待。
var builtinCustomChains = []CustomChain{
	{Name: "business-input", Parent: "MYFW-INPUT", Table: "filter", Priority: 50, Enabled: true, Description: "主机入站业务(本地服务)"},
	{Name: "acl-forward", Parent: "MYFW-FORWARD", Table: "filter", Priority: 50, Enabled: true, Description: "容器转发访问控制(Docker 端口映射)"},
	{Name: "mark-mangle", Parent: "MYFW-MANGLE", Table: "mangle", Priority: 50, Enabled: true, Description: "流量打标"},
	{Name: "nat-prerouting", Parent: "MYFW-PREROUTING", Table: "nat", Priority: 50, Enabled: true, Description: "DNAT(入向目的转换)"},
	{Name: "nat-postrouting", Parent: "MYFW-POSTROUTING", Table: "nat", Priority: 50, Enabled: true, Description: "SNAT(出向源转换)"},
}

// seedMarkKey 一次性种子标记:首次播种全部成功后写入,后续启动跳过,
// 保证用户删除预置链后重启不会重建("能成功删除")。版本化:清单变更改 v2。
const seedMarkKey = "seed.custom_chains.v1"

// SeedCustomChains 幂等预置常用策略组:
// 标记已写(done)则直接跳过;否则按 name 幂等创建,全部成功后写标记。
func SeedCustomChains(gdb *gorm.DB) error {
	var mark SystemSetting
	if err := gdb.Where("key = ?", seedMarkKey).First(&mark).Error; err == nil && mark.Value == "done" {
		return nil // 已播种过,跳过(不重建用户已删除/不覆盖已编辑的链)
	} else if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	for _, c := range builtinCustomChains {
		var exist CustomChain
		if err := gdb.Where("name = ?", c.Name).First(&exist).Error; err == nil {
			continue // 已存在,跳过
		}
		if err := gdb.Create(&c).Error; err != nil {
			return err
		}
	}
	// 全部播种成功:写一次性种子标记,后续启动跳过播种
	return gdb.Save(&SystemSetting{Key: seedMarkKey, Value: "done"}).Error
}

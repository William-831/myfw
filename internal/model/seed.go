package model

import "gorm.io/gorm"

// 常用策略组(自定义子链)预设:覆盖主机入站/容器转发/打标/NAT 常见场景,
// 启动时按 name 幂等创建,用户可直接选用,也可按需删改。
var builtinCustomChains = []CustomChain{
	{Name: "business-input", Parent: "MYFW-INPUT", Table: "filter", Priority: 50, Enabled: true, Description: "主机入站业务(本地服务)"},
	{Name: "acl-forward", Parent: "MYFW-FORWARD", Table: "filter", Priority: 50, Enabled: true, Description: "容器转发访问控制(Docker 端口映射)"},
	{Name: "mark-mangle", Parent: "MYFW-MANGLE", Table: "mangle", Priority: 50, Enabled: true, Description: "流量打标"},
	{Name: "nat-prerouting", Parent: "MYFW-PREROUTING", Table: "nat", Priority: 50, Enabled: true, Description: "DNAT(入向目的转换)"},
	{Name: "nat-postrouting", Parent: "MYFW-POSTROUTING", Table: "nat", Priority: 50, Enabled: true, Description: "SNAT(出向源转换)"},
}

// SeedCustomChains 幂等预置常用策略组:已存在(按 name)则跳过,不覆盖用户改动。
func SeedCustomChains(gdb *gorm.DB) error {
	for _, c := range builtinCustomChains {
		var exist CustomChain
		if err := gdb.Where("name = ?", c.Name).First(&exist).Error; err == nil {
			continue // 已存在,跳过
		}
		if err := gdb.Create(&c).Error; err != nil {
			return err
		}
	}
	return nil
}

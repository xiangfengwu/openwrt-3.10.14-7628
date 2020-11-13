
m = Map("wifirelay", translate("设置名称和密码"),translate("设置名称和密码连接可上网的WiFi"))

s = m:section(NamedSection, "wifirelay2g", translate("Wifi Relay"))
s.anonymous = true

s:option(Flag, "enabled", translate("Enable"))

s:option(Value, "ssid", translate("WiFi名称")).rmempty = true
s:option(Value, "key", translate("WiFi密码")).rmempty = true

v0 = s:option(ListValue, "AuthMode", translate("验证方式"))
  v0:value("WPA2PSK", translate("WPA2PSK"))
  v0:value("OPEN", translate("OPEN"))

v1 = s:option(ListValue, "EncrypType", translate("加密方式"))
  v1:value("TKIPAES", translate("TKIPAES"))
  v1:value("AES", translate("AES"))
  v1:value("TKIP", translate("TKIP"))
  v1:depends({AuthMode="WPA2PSK"})

s:option(Flag, "notscan", translate("Donot Scan"))

return m


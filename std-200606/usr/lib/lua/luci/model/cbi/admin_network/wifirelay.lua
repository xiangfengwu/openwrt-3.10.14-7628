
m = Map("wifirelay", translate("WiFi Relay"),translate("Connect to upper AP Router"))

s = m:section(NamedSection, "wifirelay2g", translate("Wifi Relay"))
s.anonymous = true

s:option(Flag, "enabled", translate("Enable"))

s:option(Value, "ssid", translate("Upper SSID")).rmempty = true
s:option(Value, "key", translate("PassWord")).rmempty = true

v0 = s:option(ListValue, "AuthMode", translate("Auth Mode"))
  v0:value("WPA2PSK", translate("WPA2PSK"))
  v0:value("OPEN", translate("OPEN"))

v1 = s:option(ListValue, "EncrypType", translate("Encryp Type"))
  v1:value("TKIPAES", translate("TKIPAES"))
  v1:value("AES", translate("AES"))
  v1:value("TKIP", translate("TKIP"))
  v1:depends({AuthMode="WPA2PSK"})

s:option(Flag, "notscan", translate("Donot Scan"))

return m


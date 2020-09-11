include $(TOPDIR)/rules.mk

PKG_NAME:=serial2tcp
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/serial2tcp
  SECTION:=utils
  CATEGORY:=Utilities
  DEPENDS:=+uci
  TITLE:=serial2tcp
endef

define Package/serial2tcp/description
  leo-exec, serial2tcp
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/serial2tcp/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/serial2tcp $(1)/bin/
endef

$(eval $(call BuildPackage,serial2tcp))

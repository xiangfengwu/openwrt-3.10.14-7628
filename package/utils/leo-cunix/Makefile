include $(TOPDIR)/rules.mk

PKG_NAME:=leo-cunix
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/leo-cunix
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=leo-cunix
endef

define Package/leo-cunix/description
  leo-cunix
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/leo-cunix/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cunix $(1)/bin/
endef

$(eval $(call BuildPackage,leo-cunix))

include $(TOPDIR)/rules.mk

PKG_NAME:=leo-aiotsdk
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/leo-aiotsdk
  SECTION:=utils
  CATEGORY:=Utilities
  DEPENDS:=+libpthread
  TITLE:=leo-aiotsdk
endef

define Package/leo-aiotsdk/description
  leo-aiotsdk
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/leo-aiotsdk/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/output/mqtt-basic-demo $(1)/bin/
endef

$(eval $(call BuildPackage,leo-aiotsdk))

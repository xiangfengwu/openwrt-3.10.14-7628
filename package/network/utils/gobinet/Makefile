include $(TOPDIR)/rules.mk

PKG_NAME:=gobinet
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/gobinet
  SECTION:=utils
  CATEGORY:=Network
  DEPENDS:=+libpthread
  TITLE:=gobinet
endef

define Package/gobinet/description
  gobinet
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/gobinet/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/GobiNet-cli $(1)/bin/
endef

$(eval $(call BuildPackage,gobinet))

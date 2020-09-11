include $(TOPDIR)/rules.mk

PKG_NAME:=expect
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/expect
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=expect
  DEPENDS:=+libtcl
endef

define Package/expect/description
  expect leo
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/expect/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/expect $(1)/bin/
endef

$(eval $(call BuildPackage,expect))

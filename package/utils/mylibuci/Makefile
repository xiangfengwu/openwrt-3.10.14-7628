include $(TOPDIR)/rules.mk

PKG_NAME:=mylibuci
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/mylibuci
  SECTION:=utils
  CATEGORY:=Utilities
  DEPENDS:=+libuci
  TITLE:=mylibuci
endef

define Package/mylibuci/description
  leo-atcmd
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/mylibuci/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mylibuci $(1)/bin/
endef

$(eval $(call BuildPackage,mylibuci))

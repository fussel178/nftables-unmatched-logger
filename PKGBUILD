# Maintainer: Ludwig Richter <riluzm@posteo.de>
pkgname=nftables-unmatched-logger
pkgver=0.2.5
pkgrel=1
pkgdesc="Log unmatched nftables packets"
arch=('any')
url='https://github.com/fussel178/nftables-unmatched-logger'
license=('MIT')
depends=('python' 'python-systemd')
source=('main.py' 'service.conf' 'sysusers.conf' 'tmpfiles.conf' 'LICENSE')
sha256sums=('b85ca4c4925cc5914331251c0c4e20d6f89651dbe627254ee9b2d8f39c3d7829'
            'df794f04c6ff3fa575fa54fba9fa7b8459c33b7d346600e20f622c756de79a98'
            '9be54ec4a5ef059b886bd928d6af55161f54bc570bffa872fa278622c547aa4b'
            '8f9ed6b0e37ae4c15584d3bf33254801f6f9ad68b2975a61b3ea4eec3faa2e80'
            'a3f0215945c437525dc6b66a29018734f088ce9395d8fa147586677107dd4a71')

package() {
  install -Dm755 'main.py' "${pkgdir}/usr/lib/${pkgname}/main.py"
  install -Dm644 'service.conf' "${pkgdir}/usr/lib/systemd/system/${pkgname}.service"
  install -Dm644 'sysusers.conf' "${pkgdir}/usr/lib/sysusers.d/${pkgname}.conf"
  install -Dm644 'tmpfiles.conf' "${pkgdir}/usr/lib/tmpfiles.d/${pkgname}.conf"
  install -Dm644 'LICENSE' "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}

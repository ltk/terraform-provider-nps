resource "nps_workshop_settings_mtls_cas" "settings" {
  certificates_pem = [
    file("${path.module}/device-issuing-ca.pem"),
  ]
}

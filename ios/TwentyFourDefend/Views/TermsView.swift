import SwiftUI

/// Displays the Privacy Policy content, sourced from www/privacy-es.html.
/// Keep these two in sync when the policy changes.
struct TermsView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                Text("Política de Privacidad")
                    .font(.title2.weight(.bold))
                    .padding(.bottom, 4)
                Text("Última actualización: 16 de abril de 2026")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.bottom, 20)

                paragraph("24Defend es una aplicación de protección contra phishing desarrollada y operada por TONLER S.A.S. (RUT 220621480018), con domicilio en Miguel Barreiro 3236, Apto. 602, Montevideo 11300, Uruguay. Esta política describe qué datos recopilamos, cómo los usamos y cómo los protegemos.")

                h2("1. Cómo funciona 24Defend")
                paragraph("24Defend crea una configuración VPN local en tu dispositivo que intercepta las consultas DNS (el paso donde tu dispositivo busca la dirección de un sitio web). La VPN es necesaria para interceptar las consultas DNS a nivel del sistema, que es la única forma de proteger al usuario en todas las aplicaciones (WhatsApp, SMS, email, navegadores) simultáneamente.")
                paragraph("La VPN realiza el filtrado DNS localmente en tu dispositivo. La gran mayoría de las consultas se resuelven en el dispositivo usando listas de bloqueo locales y modelos de inteligencia artificial sin ninguna llamada de red. Para dominios sospechosos que no están en la base de datos local, el nombre del dominio se envía a nuestros servidores para su análisis.")
                paragraph("Cuando detectamos un dominio fraudulento, bloqueamos la consulta DNS antes de que la página cargue y te notificamos.")

                h2("2. Datos que recopilamos")

                h3("2.1 Nombres de dominios bloqueados o sospechosos")
                paragraph("Cuando 24Defend bloquea un enlace o detecta un dominio sospechoso, enviamos el nombre del dominio base (por ejemplo, \"sitio-falso.com\") a nuestros servidores para mejorar la detección de amenazas. Esto nos ayuda a identificar nuevas campañas de phishing y proteger a todos los usuarios.")
                paragraph("No recopilamos dominios permitidos. Tu historial de navegación normal nunca sale de tu dispositivo.")

                h3("2.2 Estadísticas de sesión agregadas")
                paragraph("Recopilamos contadores agregados sobre el rendimiento de la aplicación: cantidad total de consultas DNS verificadas, cantidad de amenazas bloqueadas, y métricas de rendimiento. Estos datos no contienen nombres de dominios ni información de navegación.")

                h3("2.3 Identificador anónimo del dispositivo")
                paragraph("Generamos un identificador único aleatorio (UUID) para tu dispositivo. Este identificador no está vinculado a tu Apple ID, número de teléfono, correo electrónico ni ninguna información personal. Se utiliza únicamente para agrupar eventos de telemetría del mismo dispositivo.")

                h3("2.4 Registros del servidor")
                paragraph("Cuando la aplicación se comunica con nuestros servidores, los registros estándar del servidor pueden registrar temporalmente direcciones IP con fines de seguridad y prevención de abuso. Estos registros no se asocian con tu actividad de navegación y se eliminan automáticamente en un plazo de 14 días.")

                h3("2.5 Datos que NO recopilamos")
                bullets([
                    "Historial de navegación (sitios web que visitas normalmente)",
                    "Contenido de páginas web",
                    "Contraseñas o credenciales",
                    "Ubicación geográfica",
                    "Contactos, fotos u otros datos personales",
                    "Apple ID o información de la cuenta de Apple",
                ])

                h2("3. Cómo usamos los datos")
                bullets([
                    "Mejora de detección: los dominios bloqueados alimentan nuestra base de datos de amenazas, protegiendo a todos los usuarios de la red.",
                    "Rendimiento: las estadísticas agregadas nos ayudan a optimizar la aplicación.",
                    "Reportes institucionales: proporcionamos datos agregados y anonimizados a instituciones financieras sobre intentos de phishing dirigidos a sus clientes.",
                ])

                h2("4. Con quién compartimos los datos")
                paragraph("No vendemos, intercambiamos ni alquilamos tus datos a terceros. Los datos pueden ser compartidos con:")
                bullets([
                    "Instituciones financieras asociadas: datos agregados y anonimizados sobre dominios fraudulentos que imitan su marca (por ejemplo, \"se bloquearon 47 dominios de phishing dirigidos a BROU este mes\"). No se comparte información individual del usuario.",
                    "Proveedores de infraestructura: Amazon Web Services (AWS) aloja nuestros servidores bajo un acuerdo de procesamiento de datos. Los datos se almacenan cifrados en instalaciones de AWS en Estados Unidos (región us-east-1).",
                ])
                paragraph("No utilizamos SDKs de analítica de terceros, frameworks publicitarios ni herramientas de rastreo.")

                h2("5. Transferencias internacionales de datos")
                paragraph("Nuestros servidores están alojados en Estados Unidos (AWS us-east-1). Si te encuentras en Uruguay u otro país de América Latina, tus datos (nombres de dominios bloqueados y estadísticas de sesión) se transfieren y procesan en Estados Unidos. Protegemos estos datos mediante cifrado en tránsito (TLS) y en reposo (AES-256).")

                h2("6. Seguridad de los datos")
                bullets([
                    "Todas las comunicaciones entre la aplicación y nuestros servidores usan HTTPS (cifrado TLS).",
                    "Los datos se almacenan en Amazon DynamoDB con cifrado en reposo.",
                    "Los eventos de telemetría se eliminan automáticamente después de 90 días.",
                    "Los registros del servidor con direcciones IP se eliminan en un plazo de 14 días.",
                    "El acceso a los datos está restringido a miembros autorizados del equipo técnico de 24Defend.",
                ])

                h2("7. Retención de datos")
                bullets([
                    "Eventos de telemetría (dominios bloqueados): 90 días",
                    "Registros del servidor (direcciones IP): 14 días",
                    "Base de datos de dominios fraudulentos: indefinido (necesario para la protección)",
                    "Identificador de dispositivo: mientras la aplicación esté instalada",
                ])

                h2("8. Tus derechos")
                paragraph("Puedes:")
                bullets([
                    "Desinstalar la aplicación en cualquier momento para detener toda recopilación de datos",
                    "Desactivar la protección VPN desde la aplicación en cualquier momento",
                    "Contactarnos en dev@24defend.com para solicitar acceso o eliminación de tus datos",
                ])
                paragraph("Bajo la ley de protección de datos de Uruguay (Ley 18.331), tienes derecho a acceder, rectificar y eliminar tus datos personales. Responderemos a las solicitudes en un plazo de 5 días hábiles.")

                h2("9. Privacidad de menores")
                paragraph("24Defend no está dirigido a menores de 13 años. No recopilamos intencionalmente datos personales de menores. Si crees que un menor nos ha proporcionado datos, contáctanos y los eliminaremos de inmediato.")

                h2("10. Uso de VPN")
                paragraph("24Defend utiliza la API NetworkExtension de Apple (NEPacketTunnelProvider) para crear una configuración VPN local. Esta VPN:")
                bullets([
                    "Es necesaria para interceptar las consultas DNS a nivel del sistema, proporcionando protección en todas las aplicaciones",
                    "Solo intercepta consultas DNS (puerto 53)",
                    "No enruta tu tráfico web a través de servidores externos",
                    "No registra ni inspecciona el contenido de las páginas web",
                    "Realiza la mayoría del filtrado localmente en tu dispositivo usando listas de bloqueo descargadas y un modelo de inteligencia artificial en el dispositivo",
                    "Solo contacta nuestros servidores cuando un dominio es señalado como sospechoso por el análisis local (aproximadamente el 0.2% de las consultas)",
                ])

                h2("11. Cambios a esta política")
                paragraph("Podemos actualizar esta política periódicamente. Te notificaremos sobre cambios significativos a través de la aplicación. El uso continuado de 24Defend después de los cambios constituye la aceptación de la política actualizada.")

                h2("12. Contacto")
                paragraph("Para preguntas sobre privacidad, solicitudes de datos o inquietudes:")
                paragraph("TONLER S.A.S. (operador de 24Defend)\nRUT: 220621480018\nDirección: Miguel Barreiro 3236, Apto. 602, Montevideo 11300, Uruguay\nEmail: dev@24defend.com\nWeb: www.24defend.com")

                Divider()
                    .padding(.vertical, 20)

                Text("TONLER S.A.S. — Montevideo, Uruguay. RUT 220621480018.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.bottom, 4)
                Text("Esta política cumple con las directrices de revisión de la App Store de Apple (Secciones 5.1 y 5.4), la ley de protección de datos de Uruguay (Ley 18.331) y los estándares internacionales de privacidad aplicables.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding()
        }
        .navigationTitle("Política de privacidad")
        .navigationBarTitleDisplayMode(.inline)
    }

    // MARK: - Section builders

    private func h2(_ text: String) -> some View {
        Text(text)
            .font(.title3.weight(.semibold))
            .foregroundStyle(Color.accentColor)
            .padding(.top, 24)
            .padding(.bottom, 8)
    }

    private func h3(_ text: String) -> some View {
        Text(text)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.top, 12)
            .padding(.bottom, 4)
    }

    private func paragraph(_ text: String) -> some View {
        Text(text)
            .font(.subheadline)
            .foregroundStyle(.primary)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.bottom, 8)
    }

    private func bullets(_ items: [String]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(items, id: \.self) { item in
                HStack(alignment: .top, spacing: 8) {
                    Text("•")
                    Text(item)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .font(.subheadline)
            }
        }
        .padding(.bottom, 8)
    }
}

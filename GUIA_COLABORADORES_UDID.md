# 🔐 Guía de Integración UDID - Para Colaboradores

## 📋 **Resumen Ejecutivo**

Esta guía explica cómo integrar con el sistema de autenticación UDID. El flujo consta de **2 pasos principales**:
1. **Obtener UDID** (API REST)
2. **Autenticarse** (WebSocket)

---

## 🚀 **Paso 1: Obtener UDID**

### **Endpoint**
```
GET /udid/request-udid-manual/
```

### **Requisitos**
- ✅ Sin autenticación requerida
- ✅ Rate limit: 10 requests por IP cada 5 minutos
- ✅ UDID expira en 15 minutos

### **Ejemplo de Llamada**
```bash
curl -X GET "https://tu-servidor.com/udid/request-udid-manual/"
```

### **Respuesta Exitosa (HTTP 201)**
```json
{
    "udid": "a1b2c3d4",
    "expires_at": "2024-01-15T10:30:00Z",
    "status": "pending",
    "expires_in_minutes": 15
}
```

### **Respuestas de Error**
```json
// Rate limit excedido (HTTP 429)
{
    "error": "Rate limit exceeded"
}

// Error interno (HTTP 500)
{
    "error": "Internal server error"
}
```

---

## 🔌 **Paso 2: Autenticación WebSocket**

### **URL del WebSocket**
```
ws://tu-servidor.com/ws/auth/
```

### **Mensaje de Autenticación**
```json
{
    "type": "auth_with_udid",
    "udid": "a1b2c3d4",
    "app_type": "ios_mobile",
    "app_version": "1.0"
}
```

### **Campos Requeridos**
| Campo | Tipo | Descripción | Ejemplo |
|-------|------|-------------|---------|
| `type` | string | Siempre `"auth_with_udid"` | `"auth_with_udid"` |
| `udid` | string | UDID obtenido en Paso 1 | `"a1b2c3d4"` |
| `app_type` | string | Tipo de aplicación | `"android_tv"`, `"mobile"` |
| `app_version` | string | Versión de la app | `"1.0"` |

---

## 📨 **Respuestas del WebSocket**

### ✅ **Credenciales Exitosas**
```json
{
    "type": "auth_with_udid:result",
    "status": "ok",
    "result": {
        "ok": true,
        "encrypted_credentials": {
            "encrypted_data": "base64_encrypted_string",
            "encrypted_key": "rsa_encrypted_aes_key",
            "iv": "initialization_vector",
            "algorithm": "AES-256-CBC + RSA-OAEP",
            "app_type": "android_tv"
        },
        "security_info": {
            "encryption_method": "Hybrid AES-256 + RSA-OAEP",
            "app_type": "android_tv",
            "app_version": "1.0"
        },
        "expires_at": "2024-01-15T10:45:00Z"
    }
}
```

### ⏳ **Esperando Validación**
```json
{
    "type": "pending",
    "status": "not_validated",
    "detail": "Esperando validación/asociación de UDID…",
    "timeout": 600
}
```

### ❌ **Errores Comunes**
```json
// UDID inválido
{
    "type": "auth_with_udid:result",
    "status": "error",
    "result": {
        "ok": false,
        "error": "Invalid UDID",
        "code": "invalid_udid"
    }
}

// UDID expirado
{
    "type": "auth_with_udid:result",
    "status": "error",
    "result": {
        "ok": false,
        "error": "UDID has expired",
        "code": "expired"
    }
}

// Timeout
{
    "type": "timeout",
    "detail": "No se recibió validación/asociación a tiempo."
}
```

---

## 💻 **Ejemplos de Implementación**

### **JavaScript/Node.js**
```javascript
class UDIDClient {
    constructor(serverUrl) {
        this.serverUrl = serverUrl;
        this.ws = null;
    }

    async getUDID() {
        try {
            const response = await fetch(`${this.serverUrl}/udid/request-udid-manual/`);
            const data = await response.json();
            
            if (response.status === 201) {
                return data.udid;
            } else {
                throw new Error(data.error || 'Error obteniendo UDID');
            }
        } catch (error) {
            throw new Error(`Error en getUDID: ${error.message}`);
        }
    }

    async authenticate(udid, appType = 'android_tv', appVersion = '1.0') {
        return new Promise((resolve, reject) => {
            this.ws = new WebSocket(`${this.serverUrl.replace('http', 'ws')}/ws/auth/`);
            
            this.ws.onopen = () => {
                this.ws.send(JSON.stringify({
                    type: "auth_with_udid",
                    udid: udid,
                    app_type: appType,
                    app_version: appVersion
                }));
            };

            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                
                switch(data.type) {
                    case 'auth_with_udid:result':
                        if (data.status === 'ok') {
                            resolve(data.result);
                        } else {
                            reject(new Error(data.result.error));
                        }
                        this.ws.close();
                        break;
                        
                    case 'pending':
                        console.log('⏳ Esperando validación...');
                        break;
                        
                    case 'timeout':
                        reject(new Error('Timeout esperando validación'));
                        this.ws.close();
                        break;
                }
            };

            this.ws.onerror = (error) => {
                reject(new Error(`WebSocket error: ${error}`));
            };
        });
    }

    async fullFlow(appType = 'android_tv', appVersion = '1.0') {
        try {
            // Paso 1: Obtener UDID
            console.log('🔄 Obteniendo UDID...');
            const udid = await this.getUDID();
            console.log(`✅ UDID obtenido: ${udid}`);

            // Paso 2: Autenticarse
            console.log('🔌 Conectando WebSocket...');
            const credentials = await this.authenticate(udid, appType, appVersion);
            console.log('✅ Credenciales recibidas');
            
            return credentials;
        } catch (error) {
            console.error('❌ Error:', error.message);
            throw error;
        }
    }
}

// Uso
const client = new UDIDClient('https://tu-servidor.com');
client.fullFlow('android_tv', '1.0')
    .then(credentials => {
        console.log('Credenciales cifradas:', credentials.encrypted_credentials);
    })
    .catch(error => {
        console.error('Error:', error);
    });
```

### **Python**
```python
import asyncio
import websockets
import json
import requests

class UDIDClient:
    def __init__(self, server_url):
        self.server_url = server_url
        self.ws_url = server_url.replace('http', 'ws')

    def get_udid(self):
        """Paso 1: Obtener UDID"""
        try:
            response = requests.get(f"{self.server_url}/udid/request-udid-manual/")
            data = response.json()
            
            if response.status_code == 201:
                return data['udid']
            else:
                raise Exception(data.get('error', 'Error obteniendo UDID'))
        except Exception as e:
            raise Exception(f"Error en get_udid: {str(e)}")

    async def authenticate(self, udid, app_type='android_tv', app_version='1.0'):
        """Paso 2: Autenticación WebSocket"""
        try:
            async with websockets.connect(f"{self.ws_url}/ws/auth/") as websocket:
                # Enviar mensaje de autenticación
                message = {
                    "type": "auth_with_udid",
                    "udid": udid,
                    "app_type": app_type,
                    "app_version": app_version
                }
                await websocket.send(json.dumps(message))
                
                # Esperar respuesta
                while True:
                    response = await websocket.recv()
                    data = json.loads(response)
                    
                    if data['type'] == 'auth_with_udid:result':
                        if data['status'] == 'ok':
                            return data['result']
                        else:
                            raise Exception(data['result']['error'])
                    elif data['type'] == 'pending':
                        print("⏳ Esperando validación...")
                    elif data['type'] == 'timeout':
                        raise Exception("Timeout esperando validación")
                        
        except Exception as e:
            raise Exception(f"Error en authenticate: {str(e)}")

    async def full_flow(self, app_type='android_tv', app_version='1.0'):
        """Flujo completo"""
        try:
            # Paso 1: Obtener UDID
            print("🔄 Obteniendo UDID...")
            udid = self.get_udid()
            print(f"✅ UDID obtenido: {udid}")

            # Paso 2: Autenticarse
            print("🔌 Conectando WebSocket...")
            credentials = await self.authenticate(udid, app_type, app_version)
            print("✅ Credenciales recibidas")
            
            return credentials
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            raise

# Uso
async def main():
    client = UDIDClient('https://tu-servidor.com')
    try:
        credentials = await client.full_flow('android_tv', '1.0')
        print("Credenciales cifradas:", credentials['encrypted_credentials'])
    except Exception as e:
        print(f"Error: {e}")

# Ejecutar
asyncio.run(main())
```

---

## 🔧 **Configuración y Requisitos**

### **Requisitos del Cliente**
- ✅ Soporte para WebSocket (RFC 6455)
- ✅ Capacidad de manejar JSON
- ✅ Timeout configurable (recomendado: 10 minutos)
- ✅ Manejo de reconexión automática

### **Configuración del Servidor**
```python
# settings.py
UDID_WAIT_TIMEOUT = 600  # 10 minutos
UDID_ENABLE_POLLING = False  # Polling opcional
UDID_POLL_INTERVAL = 2  # Segundos entre polls
```

### **Rate Limiting**
- **API REST**: 10 requests por IP cada 5 minutos
- **WebSocket**: Sin límite específico
- **UDID**: Expira en 15 minutos

---

## 🚨 **Troubleshooting**

### **Errores Comunes**

| Error | Causa | Solución |
|-------|-------|----------|
| `Rate limit exceeded` | Demasiadas requests | Esperar 5 minutos o usar IP diferente |
| `Invalid UDID` | UDID no existe | Verificar que el UDID sea correcto |
| `UDID has expired` | UDID expirado | Obtener nuevo UDID |
| `WebSocket connection failed` | Problema de red | Verificar conectividad y URL |
| `Timeout` | No se validó en 10 min | Verificar que el operador valide el UDID |

### **Estados del UDID**
- **`pending`**: Generado, esperando validación
- **`validated`**: Validado, esperando asociación
- **`used`**: Ya utilizado (no reutilizable)
- **`expired`**: Expirado (15 minutos)
- **`revoked`**: Revocado manualmente

### **Logs y Debugging**
```javascript
// Habilitar logs detallados
const ws = new WebSocket('ws://servidor/ws/auth/');
ws.onopen = () => console.log('🔌 WebSocket conectado');
ws.onmessage = (event) => console.log('📨 Mensaje recibido:', event.data);
ws.onerror = (error) => console.error('❌ Error WebSocket:', error);
ws.onclose = (event) => console.log('🔌 WebSocket cerrado:', event.code, event.reason);
```

---

## 🔐 **Cifrado y Desencriptación**

### **Algoritmo de Cifrado Híbrido**

El sistema utiliza **cifrado híbrido** que combina:
- **AES-256-CBC** para cifrar los datos (rápido)
- **RSA-OAEP** para cifrar la clave AES (seguro)

### **Estructura de Datos Cifrados**

```json
{
    "encrypted_data": "base64_encrypted_string",     // Datos cifrados con AES-256-CBC
    "encrypted_key": "rsa_encrypted_aes_key",        // Clave AES cifrada con RSA-OAEP
    "iv": "initialization_vector",                   // Vector de inicialización (16 bytes)
    "algorithm": "AES-256-CBC + RSA-OAEP",          // Algoritmo utilizado
    "app_type": "android_tv"                         // Tipo de aplicación
}
```

### **Datos Originales (antes del cifrado)**

```json
{
    "subscriber_code": "12345",
    "sn": "ABC123456789",
    "login1": "usuario1",
    "login2": "usuario2", 
    "password": "password123",
    "pin": "1234",
    "packages": ["package1", "package2"],
    "products": ["product1", "product2"],
    "timestamp": "2024-01-15T10:30:00Z"
}
```

### **Proceso de Desencriptación**

#### **Paso 1: Desencriptar clave AES con RSA privada**
```swift
// iOS - Swift
import Security
import CryptoKit

func decryptAESKey(encryptedKey: String, privateKey: SecKey) -> Data? {
    guard let encryptedData = Data(base64Encoded: encryptedKey) else { return nil }
    
    var error: Unmanaged<CFError>?
    let decryptedData = SecKeyCreateDecryptedData(
        privateKey,
        .rsaEncryptionOAEPSHA256,
        encryptedData as CFData,
        &error
    )
    
    return decryptedData as Data?
}
```

#### **Paso 2: Desencriptar datos con AES**
```swift
// iOS - Swift
import CryptoKit

func decryptData(encryptedData: String, aesKey: Data, iv: String) -> String? {
    guard let encryptedBytes = Data(base64Encoded: encryptedData),
          let ivBytes = Data(base64Encoded: iv) else { return nil }
    
    let symmetricKey = SymmetricKey(data: aesKey)
    let sealedBox = try? AES.GCM.SealedBox(
        nonce: AES.GCM.Nonce(data: ivBytes),
        ciphertext: encryptedBytes
    )
    
    guard let box = sealedBox else { return nil }
    
    do {
        let decryptedData = try AES.GCM.open(box, using: symmetricKey)
        return String(data: decryptedData, encoding: .utf8)
    } catch {
        return nil
    }
}
```

#### **Implementación Completa en iOS**
```swift
import Foundation
import Security
import CryptoKit

class UDIDDecryptor {
    private let privateKey: SecKey
    
    init(privateKey: SecKey) {
        self.privateKey = privateKey
    }
    
    func decryptCredentials(_ encryptedCredentials: [String: Any]) -> [String: Any]? {
        guard let encryptedData = encryptedCredentials["encrypted_data"] as? String,
              let encryptedKey = encryptedCredentials["encrypted_key"] as? String,
              let iv = encryptedCredentials["iv"] as? String else {
            return nil
        }
        
        // Paso 1: Desencriptar clave AES
        guard let aesKey = decryptAESKey(encryptedKey: encryptedKey) else {
            print("❌ Error desencriptando clave AES")
            return nil
        }
        
        // Paso 2: Desencriptar datos
        guard let decryptedJson = decryptData(encryptedData: encryptedData, aesKey: aesKey, iv: iv) else {
            print("❌ Error desencriptando datos")
            return nil
        }
        
        // Paso 3: Parsear JSON
        guard let data = decryptedJson.data(using: .utf8),
              let credentials = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            print("❌ Error parseando JSON")
            return nil
        }
        
        return credentials
    }
    
    private func decryptAESKey(encryptedKey: String) -> Data? {
        guard let encryptedData = Data(base64Encoded: encryptedKey) else { return nil }
        
        var error: Unmanaged<CFError>?
        let decryptedData = SecKeyCreateDecryptedData(
            privateKey,
            .rsaEncryptionOAEPSHA256,
            encryptedData as CFData,
            &error
        )
        
        if let error = error {
            print("❌ Error RSA: \(error)")
            return nil
        }
        
        return decryptedData as Data?
    }
    
    private func decryptData(encryptedData: String, aesKey: Data, iv: String) -> String? {
        guard let encryptedBytes = Data(base64Encoded: encryptedData),
              let ivBytes = Data(base64Encoded: iv) else { return nil }
        
        let symmetricKey = SymmetricKey(data: aesKey)
        
        do {
            // AES-256-CBC decryption
            let sealedBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: ivBytes),
                ciphertext: encryptedBytes
            )
            let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
            return String(data: decryptedData, encoding: .utf8)
        } catch {
            print("❌ Error AES: \(error)")
            return nil
        }
    }
}

// Uso
let decryptor = UDIDDecryptor(privateKey: yourPrivateKey)
if let credentials = decryptor.decryptCredentials(encryptedCredentials) {
    print("✅ Credenciales desencriptadas:")
    print("Subscriber Code: \(credentials["subscriber_code"] ?? "")")
    print("SN: \(credentials["sn"] ?? "")")
    print("Password: \(credentials["password"] ?? "")")
    print("PIN: \(credentials["pin"] ?? "")")
}
```

### **Requisitos para iOS**

#### **1. Frameworks Necesarios**
```swift
import Security      // Para RSA
import CryptoKit    // Para AES (iOS 13+)
// O usar CommonCrypto para iOS < 13
```

#### **2. Clave Privada RSA**
- **Formato**: PEM o PKCS#12
- **Tamaño**: 2048 bits mínimo
- **Algoritmo**: RSA con OAEP padding
- **Hash**: SHA-256

#### **3. Configuración de Seguridad**
```swift
// Configurar Keychain para almacenar clave privada
let keychainQuery: [String: Any] = [
    kSecClass as String: kSecClassKey,
    kSecAttrApplicationTag as String: "com.tuapp.udid.privatekey",
    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
    kSecReturnRef as String: true
]
```

### **Elementos de la Respuesta WebSocket**

| Campo | Tipo | Descripción | Acción Requerida |
|-------|------|-------------|------------------|
| `type` | string | Tipo de mensaje | Verificar que sea `"auth_with_udid:result"` |
| `status` | string | Estado de la operación | `"ok"` = exitoso, `"error"` = falló |
| `result.ok` | boolean | Indica si la operación fue exitosa | `true` = proceder, `false` = manejar error |
| `result.encrypted_credentials` | object | Credenciales cifradas | **Desencriptar usando clave privada** |
| `result.security_info` | object | Información de seguridad | Verificar algoritmo y app_type |
| `result.expires_at` | string | Fecha de expiración | Verificar que no haya expirado |

### **Flujo de Desencriptación

1. **Recibir respuesta del WebSocket**
2. **Verificar `status === "ok"`**
3. **Extraer `encrypted_credentials`**
4. **Desencriptar `encrypted_key` con RSA privada** → Obtener clave AES
5. **Desencriptar `encrypted_data` con AES** → Obtener JSON
6. **Parsear JSON** → Obtener credenciales
7. **Usar credenciales** para autenticación

### **Implementación para Android/Java**

```java
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.util.Base64;
import org.json.JSONObject;

public class UDIDDecryptor {
    private PrivateKey privateKey;
    
    public UDIDDecryptor(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
    
    public JSONObject decryptCredentials(JSONObject encryptedCredentials) throws Exception {
        String encryptedData = encryptedCredentials.getString("encrypted_data");
        String encryptedKey = encryptedCredentials.getString("encrypted_key");
        String iv = encryptedCredentials.getString("iv");
        
        // Paso 1: Desencriptar clave AES con RSA
        byte[] aesKey = decryptAESKey(encryptedKey);
        
        // Paso 2: Desencriptar datos con AES
        String decryptedJson = decryptData(encryptedData, aesKey, iv);
        
        // Paso 3: Parsear JSON
        return new JSONObject(decryptedJson);
    }
    
    private byte[] decryptAESKey(String encryptedKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedKey);
        return cipher.doFinal(encryptedBytes);
    }
    
    private String decryptData(String encryptedData, byte[] aesKey, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
        
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        
        return new String(decryptedBytes, "UTF-8");
    }
}

// Uso
PrivateKey privateKey = loadPrivateKeyFromKeyStore();
UDIDDecryptor decryptor = new UDIDDecryptor(privateKey);
JSONObject credentials = decryptor.decryptCredentials(encryptedCredentials);

System.out.println("Subscriber Code: " + credentials.getString("subscriber_code"));
System.out.println("SN: " + credentials.getString("sn"));
System.out.println("Password: " + credentials.getString("password"));
```

### **Manejo de Errores de Desencriptación**

```swift
// iOS - Swift
func handleDecryptionError(_ error: Error) {
    switch error {
    case is DecryptionError:
        print("❌ Error de desencriptación: \(error)")
        // Reintentar o solicitar nuevo UDID
    case is JSONParsingError:
        print("❌ Error parseando JSON: \(error)")
        // Verificar integridad de datos
    default:
        print("❌ Error desconocido: \(error)")
        // Log para debugging
    }
}
```

```java
// Android - Java
public void handleDecryptionError(Exception error) {
    if (error instanceof javax.crypto.BadPaddingException) {
        System.err.println("❌ Error de desencriptación: " + error.getMessage());
        // Reintentar o solicitar nuevo UDID
    } else if (error instanceof org.json.JSONException) {
        System.err.println("❌ Error parseando JSON: " + error.getMessage());
        // Verificar integridad de datos
    } else {
        System.err.println("❌ Error desconocido: " + error.getMessage());
        // Log para debugging
    }
}
```

---

## 📞 **Soporte**

### **Contacto Técnico**
- **Email**: soporte@tu-empresa.com
- **Slack**: #udid-support
- **Documentación**: https://docs.tu-empresa.com/udid

### **Recursos Adicionales**
- 📚 [Documentación API completa](https://docs.tu-empresa.com/api)
- 🔧 [Herramientas de testing](https://tools.tu-empresa.com/udid)
- 📊 [Dashboard de monitoreo](https://monitor.tu-empresa.com)

---

## ✅ **Checklist de Implementación**

- [ ] Configurar URL del servidor
- [ ] Implementar llamada a `request-udid-manual/`
- [ ] Manejar respuestas de error de la API
- [ ] Implementar conexión WebSocket
- [ ] Enviar mensaje de autenticación correcto
- [ ] Manejar respuesta `pending`
- [ ] Manejar respuesta exitosa con credenciales
- [ ] Manejar errores y timeouts
- [ ] Implementar reconexión automática
- [ ] Agregar logging para debugging
- [ ] Probar con diferentes `app_type` y `app_version`
- [ ] Validar manejo de UDID expirados

---

**🎯 ¡Listo para implementar!** Si tienes dudas, consulta la sección de troubleshooting o contacta al equipo de soporte.

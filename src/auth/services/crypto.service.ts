import { Injectable } from "@nestjs/common"
import type { ConfigService } from "@nestjs/config"
import * as crypto from "crypto"

@Injectable()
export class CryptoService {
  private readonly algorithm = "aes-256-gcm"
  private readonly secretKey: Buffer

  constructor(private configService: ConfigService) {
    const key = this.configService.get<string>("ENCRYPTION_KEY")
    if (!key || key.length !== 32) {
      throw new Error("ENCRYPTION_KEY must be exactly 32 characters long")
    }
    this.secretKey = Buffer.from(key, "utf8")
  }

  /**
   * Encrypt a string value
   */
  encrypt(text: string): string {
    const iv = crypto.randomBytes(16)
    const cipher = crypto.createCipher(this.algorithm, this.secretKey)
    cipher.setAAD(Buffer.from("mixmatch-auth", "utf8"))

    let encrypted = cipher.update(text, "utf8", "hex")
    encrypted += cipher.final("hex")

    const authTag = cipher.getAuthTag()

    // Combine iv, authTag, and encrypted data
    return `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted}`
  }

  /**
   * Decrypt a string value
   */
  decrypt(encryptedData: string): string {
    const [ivHex, authTagHex, encrypted] = encryptedData.split(":")

    const iv = Buffer.from(ivHex, "hex")
    const authTag = Buffer.from(authTagHex, "hex")

    const decipher = crypto.createDecipher(this.algorithm, this.secretKey)
    decipher.setAAD(Buffer.from("mixmatch-auth", "utf8"))
    decipher.setAuthTag(authTag)

    let decrypted = decipher.update(encrypted, "hex", "utf8")
    decrypted += decipher.final("utf8")

    return decrypted
  }

  /**
   * Generate a secure random state for OAuth
   */
  generateState(): string {
    return crypto.randomBytes(32).toString("hex")
  }
}

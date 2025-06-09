import { Injectable, BadRequestException, InternalServerErrorException } from "@nestjs/common"
import type { ConfigService } from "@nestjs/config"
import type { UsersService } from "../../users/users.service"
import type { AuthService } from "../auth.service"
import type { CryptoService } from "../services/crypto.service"
import type { SpotifyUser, SpotifyTokenResponse } from "./interfaces/spotify-user.interface"
import type { SpotifyCallbackDto } from "./dto/spotify-callback.dto"
import { MusicProvider } from "@prisma/client"

@Injectable()
export class SpotifyOAuthService {
  private readonly spotifyClientId: string
  private readonly spotifyClientSecret: string
  private readonly spotifyRedirectUri: string
  private readonly spotifyAuthUrl = "https://accounts.spotify.com/authorize"
  private readonly spotifyTokenUrl = "https://accounts.spotify.com/api/token"
  private readonly spotifyApiUrl = "https://api.spotify.com/v1"

  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
    private readonly authService: AuthService,
    private readonly cryptoService: CryptoService,
  ) {
    this.spotifyClientId = this.configService.get<string>("SPOTIFY_CLIENT_ID")!
    this.spotifyClientSecret = this.configService.get<string>("SPOTIFY_CLIENT_SECRET")!
    this.spotifyRedirectUri = this.configService.get<string>("SPOTIFY_REDIRECT_URI")!

    if (!this.spotifyClientId || !this.spotifyClientSecret || !this.spotifyRedirectUri) {
      throw new Error("Missing required Spotify OAuth configuration")
    }
  }

  /**
   * Generate Spotify OAuth authorization URL
   */
  getAuthorizationUrl(): { url: string; state: string } {
    const state = this.cryptoService.generateState()
    const scopes = [
      "user-read-private",
      "user-read-email",
      "user-library-read",
      "user-top-read",
      "playlist-read-private",
      "playlist-read-collaborative",
    ].join(" ")

    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.spotifyClientId,
      scope: scopes,
      redirect_uri: this.spotifyRedirectUri,
      state,
      show_dialog: "true", // Force user to approve app each time
    })

    const url = `${this.spotifyAuthUrl}?${params.toString()}`

    return { url, state }
  }

  /**
   * Exchange authorization code for access and refresh tokens
   */
  private async exchangeCodeForTokens(code: string): Promise<SpotifyTokenResponse> {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.spotifyRedirectUri,
    })

    const authHeader = Buffer.from(`${this.spotifyClientId}:${this.spotifyClientSecret}`).toString("base64")

    try {
      const response = await fetch(this.spotifyTokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${authHeader}`,
        },
        body: params.toString(),
      })

      if (!response.ok) {
        const error = await response.text()
        throw new Error(`Spotify token exchange failed: ${error}`)
      }

      return await response.json()
    } catch (error) {
      throw new InternalServerErrorException(`Failed to exchange code for tokens: ${error.message}`)
    }
  }

  /**
   * Fetch user profile from Spotify API
   */
  private async fetchSpotifyUserProfile(accessToken: string): Promise<SpotifyUser> {
    try {
      const response = await fetch(`${this.spotifyApiUrl}/me`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      })

      if (!response.ok) {
        const error = await response.text()
        throw new Error(`Spotify API request failed: ${error}`)
      }

      return await response.json()
    } catch (error) {
      throw new InternalServerErrorException(`Failed to fetch user profile: ${error.message}`)
    }
  }

  /**
   * Handle Spotify OAuth callback
   */
  async handleCallback(callbackDto: SpotifyCallbackDto): Promise<{
    user: any
    tokens: { accessToken: string; refreshToken: string }
  }> {
    if (callbackDto.error) {
      throw new BadRequestException(`Spotify OAuth error: ${callbackDto.error}`)
    }

    // Exchange code for tokens
    const tokenResponse = await this.exchangeCodeForTokens(callbackDto.code)

    // Fetch user profile
    const spotifyUser = await this.fetchSpotifyUserProfile(tokenResponse.access_token)

    // Check if user already exists
    let user = await this.usersService.findByMusicId(spotifyUser.id)

    if (user) {
      // Update existing user's tokens
      user = await this.usersService.update(user.id, {
        accessToken: this.cryptoService.encrypt(tokenResponse.access_token),
        refreshToken: this.cryptoService.encrypt(tokenResponse.refresh_token),
        displayName: spotifyUser.display_name || user.displayName,
        email: spotifyUser.email || user.email,
      })
    } else {
      // Create new user
      user = await this.usersService.create({
        email: spotifyUser.email,
        displayName: spotifyUser.display_name || `Spotify User ${spotifyUser.id}`,
        musicProvider: MusicProvider.SPOTIFY,
        musicId: spotifyUser.id,
        accessToken: this.cryptoService.encrypt(tokenResponse.access_token),
        refreshToken: this.cryptoService.encrypt(tokenResponse.refresh_token),
      })
    }

    // Generate JWT tokens for our app
    const jwtTokens = await this.authService.generateTokens(user)

    return {
      user: user.toPublic(),
      tokens: jwtTokens,
    }
  }

  /**
   * Refresh Spotify access token
   */
  async refreshSpotifyToken(userId: string): Promise<string> {
    const user = await this.usersService.findOne(userId)

    if (user.musicProvider !== MusicProvider.SPOTIFY) {
      throw new BadRequestException("User is not a Spotify user")
    }

    const decryptedRefreshToken = this.cryptoService.decrypt(user.refreshToken)

    const params = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: decryptedRefreshToken,
    })

    const authHeader = Buffer.from(`${this.spotifyClientId}:${this.spotifyClientSecret}`).toString("base64")

    try {
      const response = await fetch(this.spotifyTokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${authHeader}`,
        },
        body: params.toString(),
      })

      if (!response.ok) {
        const error = await response.text()
        throw new Error(`Spotify token refresh failed: ${error}`)
      }

      const tokenResponse: SpotifyTokenResponse = await response.json()

      // Update user's access token (and refresh token if provided)
      await this.usersService.update(userId, {
        accessToken: this.cryptoService.encrypt(tokenResponse.access_token),
        ...(tokenResponse.refresh_token && {
          refreshToken: this.cryptoService.encrypt(tokenResponse.refresh_token),
        }),
      })

      return tokenResponse.access_token
    } catch (error) {
      throw new InternalServerErrorException(`Failed to refresh Spotify token: ${error.message}`)
    }
  }

  /**
   * Get decrypted Spotify access token for a user
   */
  async getDecryptedAccessToken(userId: string): Promise<string> {
    const user = await this.usersService.findOne(userId)

    if (user.musicProvider !== MusicProvider.SPOTIFY) {
      throw new BadRequestException("User is not a Spotify user")
    }

    return this.cryptoService.decrypt(user.accessToken)
  }
}

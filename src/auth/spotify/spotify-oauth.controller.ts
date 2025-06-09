import { Controller, Get, Query, HttpStatus } from "@nestjs/common"
import type { Response } from "express"
import type { SpotifyOAuthService } from "./spotify-oauth.service"
import type { SpotifyCallbackDto } from "./dto/spotify-callback.dto"

@Controller("auth/spotify")
export class SpotifyOAuthController {
  constructor(private readonly spotifyOAuthService: SpotifyOAuthService) {}

  /**
   * Initiate Spotify OAuth flow
   * GET /auth/spotify
   */
  @Get()
  async initiateAuth(res: Response) {
    const { url, state } = this.spotifyOAuthService.getAuthorizationUrl()

    // Store state in session/cookie for validation (optional but recommended)
    res.cookie("spotify_oauth_state", state, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 10 * 60 * 1000, // 10 minutes
    })

    return res.redirect(url)
  }

  /**
   * Handle Spotify OAuth callback
   * GET /auth/spotify/callback
   */
  @Get("callback")
  async handleCallback(query: SpotifyCallbackDto, res: Response) {
    try {
      const result = await this.spotifyOAuthService.handleCallback(query)

      // Set JWT tokens as HTTP-only cookies
      res.cookie("access_token", result.tokens.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 60 * 60 * 1000, // 1 hour
      })

      res.cookie("refresh_token", result.tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      })

      // Redirect to frontend success page
      const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000"
      return res.redirect(`${frontendUrl}/auth/success`)
    } catch (error) {
      // Redirect to frontend error page
      const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000"
      return res.redirect(`${frontendUrl}/auth/error?message=${encodeURIComponent(error.message)}`)
    }
  }

  /**
   * Get current user's Spotify profile (protected route example)
   */
  @Get("profile")
  async getProfile(@Query("userId") userId: string) {
    try {
      const accessToken = await this.spotifyOAuthService.getDecryptedAccessToken(userId)

      const response = await fetch("https://api.spotify.com/v1/me", {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      })

      if (!response.ok) {
        // Try to refresh token if expired
        const newAccessToken = await this.spotifyOAuthService.refreshSpotifyToken(userId)
        const retryResponse = await fetch("https://api.spotify.com/v1/me", {
          headers: {
            Authorization: `Bearer ${newAccessToken}`,
          },
        })

        if (!retryResponse.ok) {
          throw new Error("Failed to fetch Spotify profile")
        }

        return await retryResponse.json()
      }

      return await response.json()
    } catch (error) {
      return {
        error: error.message,
        status: HttpStatus.INTERNAL_SERVER_ERROR,
      }
    }
  }
}

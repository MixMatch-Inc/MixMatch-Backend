export interface SpotifyUser {
  id: string
  display_name: string
  email?: string
  images?: Array<{
    url: string
    height: number
    width: number
  }>
  followers?: {
    total: number
  }
  country?: string
  product?: string
}

export interface SpotifyTokenResponse {
  access_token: string
  token_type: string
  scope: string
  expires_in: number
  refresh_token: string
}

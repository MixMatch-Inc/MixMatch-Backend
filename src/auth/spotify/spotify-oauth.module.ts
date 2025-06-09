import { Module } from "@nestjs/common"
import { ConfigModule } from "@nestjs/config"
import { SpotifyOAuthService } from "./spotify-oauth.service"
import { SpotifyOAuthController } from "./spotify-oauth.controller"
import { UsersModule } from "../../users/users.module"
import { AuthModule } from "../auth.module"
import { CryptoService } from "../services/crypto.service"

@Module({
  imports: [ConfigModule, UsersModule, AuthModule],
  providers: [SpotifyOAuthService, CryptoService],
  controllers: [SpotifyOAuthController],
  exports: [SpotifyOAuthService],
})
export class SpotifyOAuthModule {}

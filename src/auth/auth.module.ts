import { Module } from "@nestjs/common"
import { JwtModule } from "@nestjs/jwt"
import { PassportModule } from "@nestjs/passport"
import { ConfigModule, ConfigService } from "@nestjs/config"
import { AuthService } from "./auth.service"
import { JwtStrategy } from "./strategies/jwt.strategy"
import { UsersModule } from "../users/users.module"
import { AuthController } from "./auth.controller"
import { User } from "src/users/entities/user.entity"
import { AppleAuthService } from "./apple/apple-auth.service"
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    UsersModule,
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>("JWT_SECRET"),
        signOptions: {
          expiresIn: "1h", 
        },
      }),
    }),
  ],
  providers: [AuthService, JwtStrategy, AppleAuthService],
  exports: [AuthService],
  controllers: [AuthController],
})
export class AuthModule {}

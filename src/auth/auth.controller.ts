import { Controller, Get, Post, Body, Res, Req, UseGuards, Query } from '@nestjs/common';
import { AppleAuthService } from './apple/apple-auth.service';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { Response, Request } from 'express';
import { ConfigService } from '@nestjs/config';

@Controller('auth/apple')
export class AuthController {
  constructor(
    private readonly appleAuthService: AppleAuthService,
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  //
  @Get('developer-token')
  async getDeveloperToken() {
    const developerToken = await this.appleAuthService.getMusicKitDeveloperToken();
    return { developerToken };
  }

  
  @Post('callback')
  async signInWithAppleCallback(@Body() body: { code: string; id_token?: string; user?: { email: string; name: { firstName: string; lastName: string } } }, @Res() res: Response) {
    const { code, user: appleProvidedUser } = body;

    try {
      const appleAuthData = await this.appleAuthService.validateSignInWithAppleCode(code);

      let user = await this.usersRepository.findOne({ where: { appleUserId: appleAuthData.appleUserId } });

      if (!user) {
        
        user = this.usersRepository.create({
          appleUserId: appleAuthData.appleUserId,
          email: appleAuthData.email || appleProvidedUser?.email,
          firstName: appleProvidedUser?.name?.firstName,
          lastName: appleProvidedUser?.name?.lastName,
          
          appleRefreshToken: appleAuthData.appleRefreshToken,
        });
        await this.usersRepository.save(user);
        console.log(`New user created for Apple ID: ${user.appleUserId}`);
      } else {
        
        if (appleAuthData.appleRefreshToken && user.appleRefreshToken !== appleAuthData.appleRefreshToken) {
          user.appleRefreshToken = appleAuthData.appleRefreshToken; 
          await this.usersRepository.save(user);
        }
        console.log(`User logged in with Apple ID: ${user.appleUserId}`);
      }

      
      const payload = { userId: user.id, appleUserId: user.appleUserId, email: user.email };
      const authToken = this.jwtService.sign(payload);

      
      
      
      return res.json({ message: 'Login successful', user, token: authToken });

    } catch (error) {
      console.error('Apple Sign-In callback error:', error);
      return res.status(401).json({ message: 'Authentication failed', error: error.message });
    }
  }

  
  @Post('connect-music')
  @UseGuards( /* Your AuthGuard for your internal app JWT */ ) 
  async connectMusicAccount(@Req() req: Request, @Body('musicUserToken') musicUserToken: string, @Body('storefrontId') storefrontId?: string) {
    
    const userId = req.user['userId']; 

    if (!musicUserToken) {
      throw new UnauthorizedException('Music User Token is required.');
    }

    const user = await this.usersRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new UnauthorizedException('User not found.');
    }

    
    user.musicUserToken = musicUserToken;
    user.musicStorefrontId = storefrontId;
    user.musicUserTokenExpiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 180); // Music User Token validity can vary, roughly 6 months

    await this.usersRepository.save(user);

    return { message: 'Apple Music account linked successfully!' };
  }

  
  @Get('music-status')
  @UseGuards( /* Your AuthGuard for your internal app JWT */ )
  async getMusicStatus(@Req() req: Request) {
    const userId = req.user['userId'];
    const user = await this.usersRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new UnauthorizedException('User not found.');
    }

    return {
      isMusicKitLinked: !!user.musicUserToken,
      storefrontId: user.musicStorefrontId,
      
      
      
    };
  }
}
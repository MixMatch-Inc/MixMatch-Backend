import { Injectable, InternalServerErrorException, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import * as appleSignin from 'apple-signin'; // Good library for Apple Sign-In verification

@Injectable()
export class AppleAuthService {
  private readonly logger = new Logger(AppleAuthService.name);
  private musicKitDeveloperToken: string | null = null;
  private musicKitDeveloperTokenExpiry: Date | null = null;

  constructor(private configService: ConfigService) {
    this.scheduleDeveloperTokenRefresh();
  }

  /**
   * Generates and caches the Apple Music Developer Token.
   */
  public async getMusicKitDeveloperToken(): Promise<string> {
    const musicKitKeyId = this.configService.get<string>('app.apple.musicKitKeyId');
    const teamId = this.configService.get<string>('app.apple.teamId');
    const privateKeyPath = this.configService.get<string>('app.apple.musicKitPrivateKeyPath');

    if (!musicKitKeyId || !teamId || !privateKeyPath) {
      throw new InternalServerErrorException('Apple MusicKit configuration is missing.');
    }

    
    if (this.musicKitDeveloperToken && this.musicKitDeveloperTokenExpiry && this.musicKitDeveloperTokenExpiry > new Date()) {
      return this.musicKitDeveloperToken;
    }

    try {
      const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
      const now = Math.floor(Date.now() / 1000); 
      const expiresIn = 15777000; 
      const exp = now + expiresIn;

      const token = jwt.sign(
        {}, 
        privateKey,
        {
          algorithm: 'ES256',
          expiresIn: expiresIn,
          issuer: teamId,
          header: {
            kid: musicKitKeyId,
          },
        }
      );

      this.musicKitDeveloperToken = token;
      this.musicKitDeveloperTokenExpiry = new Date((exp - 600) * 1000); // Set expiry slightly before actual expiry for proactive refresh
      this.logger.log('New Apple Music Developer Token generated successfully.');
      return token;
    } catch (error) {
      this.logger.error('Error generating Apple Music Developer Token:', error.message, error.stack);
      throw new InternalServerErrorException('Failed to generate Apple Music Developer Token.');
    }
  }

  private scheduleDeveloperTokenRefresh() {
    
    setInterval(async () => {
      if (!this.musicKitDeveloperToken || (this.musicKitDeveloperTokenExpiry && this.musicKitDeveloperTokenExpiry <= new Date())) {
        await this.getMusicKitDeveloperToken();
      }
    }, 1000 * 60 * 60 * 24 * 30 * 5); 
  }

  /**
   * Validates the authorization code from Sign in with Apple and returns user data.
   */
  public async validateSignInWithAppleCode(authorizationCode: string): Promise<any> {
    const clientId = this.configService.get<string>('app.apple.signInClientId');
    const keyId = this.configService.get<string>('app.apple.signInKeyId');
    const teamId = this.configService.get<string>('app.apple.teamId');
    const privateKeyPath = this.configService.get<string>('app.apple.signInPrivateKeyPath');
    const redirectUri = this.configService.get<string>('app.apple.signInRedirectUri');

    if (!clientId || !keyId || !teamId || !privateKeyPath || !redirectUri) {
      throw new InternalServerErrorException('Sign in with Apple configuration is missing.');
    }

    try {
      const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

      // Use apple-signin library for convenience
      const clientSecret = appleSignin.getClientSecret({
        clientID: clientId,
        teamID: teamId,
        keyIdentifier: keyId,
        privateKey,
      });

      const response = await appleSignin.get
        .authorizationToken(authorizationCode, {
          clientID: clientId,
          clientSecret,
          redirectUri,
        });

      if (!response || !response.id_token) {
        throw new UnauthorizedException('Failed to get id_token from Apple.');
      }

      
      const decodedToken = await appleSignin.verifyIdToken(response.id_token, {
        clientID: clientId,
        nonce: '', 
      });

      return {
        appleUserId: decodedToken.sub,
        email: decodedToken.email,
        emailVerified: decodedToken.email_verified,
        isPrivateEmail: decodedToken.is_private_email,
        appleRefreshToken: response.refresh_token, 
        
        
      };
    } catch (error) {
      this.logger.error('Error validating Sign in with Apple code:', error.message, error.stack);
      throw new UnauthorizedException('Invalid Apple Sign-In authorization code.');
    }
  }

  /**
   * Refreshes the Sign in with Apple access token using the refresh token.
   */
  public async refreshSignInWithAppleToken(refreshToken: string): Promise<any> {
    const clientId = this.configService.get<string>('app.apple.signInClientId');
    const keyId = this.configService.get<string>('app.apple.signInKeyId');
    const teamId = this.configService.get<string>('app.apple.teamId');
    const privateKeyPath = this.configService.get<string>('app.apple.signInPrivateKeyPath');

    if (!clientId || !keyId || !teamId || !privateKeyPath) {
      throw new InternalServerErrorException('Sign in with Apple configuration is missing for refresh.');
    }

    try {
      const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

      const clientSecret = appleSignin.getClientSecret({
        clientID: clientId,
        teamID: teamId,
        keyIdentifier: keyId,
        privateKey,
      });

      const response = await appleSignin.get
        .refreshToken(refreshToken, {
          clientID: clientId,
          clientSecret,
        });

      if (!response || !response.access_token) {
        throw new UnauthorizedException('Failed to refresh Apple access token.');
      }

      return {
        accessToken: response.access_token,
        refreshToken: response.refresh_token || refreshToken, 
        idToken: response.id_token,
      };
    } catch (error) {
      this.logger.error('Error refreshing Sign in with Apple token:', error.message, error.stack);
      throw new UnauthorizedException('Failed to refresh Apple Sign-In token.');
    }
  }
}
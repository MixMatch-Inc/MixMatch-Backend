import { IsNotEmpty, IsOptional, IsString } from "class-validator"

export class SpotifyCallbackDto {
  @IsNotEmpty()
  @IsString()
  code: string

  @IsOptional()
  @IsString()
  state?: string

  @IsOptional()
  @IsString()
  error?: string
}

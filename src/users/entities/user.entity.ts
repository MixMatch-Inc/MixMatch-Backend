import { Entity, PrimaryGeneratedColumn, Column, Unique } from 'typeorm';

@Entity()
@Unique(['appleUserId']) 
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: true })
  email?: string; 

  @Column({ nullable: true })
  firstName?: string; 

  @Column({ nullable: true })
  lastName?: string; 

  @Column({ nullable: true })
  appleUserId?: string; 

  @Column({ type: 'text', nullable: true })
  appleRefreshToken?: string; 
  
  @Column({ type: 'text', nullable: true })
  musicUserToken?: string; 

  @Column({ nullable: true })
  musicStorefrontId?: string; 

  @Column({ type: 'timestamp', nullable: true })
  musicUserTokenExpiresAt?: Date; 
}
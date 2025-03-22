import mongoose, { Schema, Document } from 'mongoose';
import * as bcrypt from 'bcrypt';

export enum UserRole {
  DJ = "dj",
  EVENT_PLANNER = "event_planner",
  ADMIN = "admin"
}

export interface ISocialLogin {
  googleId?: string;
  appleId?: string;
}

export interface IUser extends Document {
  fullName: string;
  email: string;
  password: string;
  role: UserRole;
  phone?: string;
  profilePicture?: string;
  verified: boolean;
  resetPasswordToken?: string;
  resetPasswordExpires?: Date;
  socialLogin?: ISocialLogin;
  createdAt: Date;
  updatedAt: Date;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

const UserSchema: Schema = new Schema(
  {
    fullName: {
      type: String,
      required: [true, "Full name is required"],
      trim: true
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      trim: true,
      lowercase: true,
      match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, "Please provide a valid email"]
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [6, "Password must be at least 6 characters"]
    },
    role: {
      type: String,
      enum: Object.values(UserRole),
      required: [true, "User role is required"]
    },
    phone: {
      type: String,
      trim: true
    },
    profilePicture: {
      type: String
    },
    verified: {
      type: Boolean,
      default: false
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    socialLogin: {
      googleId: String,
      appleId: String
    }
  },
  {
    timestamps: true
  }
);

// Hash password before saving
UserSchema.pre<IUser>('save', async function(next) {
  if (this.isModified('password')) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
  next();
});

// Method to check if password is correct
UserSchema.methods.comparePassword = async function(this: IUser, candidatePassword: string): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

export default mongoose.model<IUser>('User', UserSchema); 
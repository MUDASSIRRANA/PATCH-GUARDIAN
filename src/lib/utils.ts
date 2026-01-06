import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"
import * as bcrypt from 'bcryptjs'
import * as crypto from 'crypto'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// Password validation
export const validatePassword = (password: string): { isValid: boolean; message: string } => {
  if (password.length < 8) {
    return { isValid: false, message: 'Password must be at least 8 characters long' }
  }

  if (!/[A-Z]/.test(password)) {
    return { isValid: false, message: 'Password must contain at least one uppercase letter' }
  }

  if (!/[a-z]/.test(password)) {
    return { isValid: false, message: 'Password must contain at least one lowercase letter' }
  }

  if (!/[0-9]/.test(password)) {
    return { isValid: false, message: 'Password must contain at least one number' }
  }

  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return { isValid: false, message: 'Password must contain at least one special character' }
  }

  return { isValid: true, message: 'Password is valid' }
}

// Hash password
export const hashPassword = async (password: string): Promise<string> => {
  const salt = await bcrypt.genSalt(12)
  return bcrypt.hash(password, salt)
}

// Compare password with hash
export const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  return bcrypt.compare(password, hash)
}

// Encrypt data
export const encryptData = (data: string, encryptionKey: string): string => {
  const iv = crypto.randomBytes(16)
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(encryptionKey, 'hex'), iv)
  
  let encrypted = cipher.update(data, 'utf8', 'hex')
  encrypted += cipher.final('hex')
  
  const authTag = cipher.getAuthTag()
  
  // Return IV + Auth Tag + Encrypted Data
  return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted
}

// Decrypt data
export const decryptData = (encryptedData: string, encryptionKey: string): string => {
  const [ivHex, authTagHex, encryptedText] = encryptedData.split(':')
  
  const iv = Buffer.from(ivHex, 'hex')
  const authTag = Buffer.from(authTagHex, 'hex')
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(encryptionKey, 'hex'), iv)
  
  decipher.setAuthTag(authTag)
  
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8')
  decrypted += decipher.final('utf8')
  
  return decrypted
}

// Generate secure random token
export const generateToken = (length: number = 32): string => {
  return crypto.randomBytes(length).toString('hex')
}

// Format error messages
export const formatErrorMessage = (error: unknown): string => {
  if (error instanceof Error) return error.message
  return String(error)
}

// Validate email format
export const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
} 
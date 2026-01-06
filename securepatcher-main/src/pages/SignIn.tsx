import React, { useState } from "react";
import { Eye, EyeOff, Mail, AlertCircle, CheckCircle, Loader2, Lock, Shield } from "lucide-react";
import { useNavigate } from "react-router-dom";

const API_URL = 'http://localhost:3001/api';

type ErrorType = {
  field: 'email' | 'password' | 'otp' | 'general' | null;
  message: string;
  remainingAttempts?: number;
  isLocked?: boolean;
  lockUntil?: string;
  isBlocked?: boolean;
} | null;

const SignIn = () => {
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ErrorType>(null);
  const [isSuccess, setIsSuccess] = useState(false);
  const [lockTimer, setLockTimer] = useState<ReturnType<typeof setInterval> | null>(null);
  const [showOtpInput, setShowOtpInput] = useState(false);
  const [tempToken, setTempToken] = useState<string | null>(null);
  const [verificationAttempts, setVerificationAttempts] = useState(3);

  const startLockCountdown = (lockUntil: string) => {
    if (lockTimer !== null) {
      clearInterval(lockTimer);
    }
    const updateLockMessage = () => {
      const now = new Date().getTime();
      const lockTime = new Date(lockUntil).getTime();
      const remainingTime = Math.ceil((lockTime - now) / (60 * 1000));
      if (remainingTime <= 0) {
        if (lockTimer !== null) {
          clearInterval(lockTimer);
        }
        setError(null);
        return;
      }
      setError(prev => prev ? {
        ...prev,
        message: `Account is temporarily locked. Please try again in ${remainingTime} minutes.`
      } : null);
    };
    updateLockMessage();
    const timer = setInterval(updateLockMessage, 60 * 1000);
    setLockTimer(timer);
  };

  const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setEmail(e.target.value);
    if (error?.field === 'email') {
      setError(null);
    }
  };

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setPassword(e.target.value);
    if (error?.field === 'password') {
      setError(null);
    }
  };

  const handleOtpChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setOtp(e.target.value);
    if (error?.field === 'otp') {
      setError(null);
    }
  };

  const formatErrorMessage = (error: ErrorType) => {
    if (!error) return '';
    let message = error.message;
    if (error.remainingAttempts !== undefined && error.remainingAttempts > 0) {
      message += ` (${error.remainingAttempts} ${error.remainingAttempts === 1 ? 'attempt' : 'attempts'} remaining)`;
    }
    return message;
  };

  // Handle password submit (first step)
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSuccess(false);
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError({
        field: 'email',
        message: 'Please enter a valid email address'
      });
      return;
    }
    if (!password.trim()) {
      setError({
        field: 'password',
        message: 'Password is required'
      });
      return;
    }
    try {
      setIsLoading(true);
      const response = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          email: email.trim().toLowerCase(),
          password
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        switch (response.status) {
          case 423:
            setError({
              field: 'general',
              message: data.message || 'Account is locked',
              isLocked: true,
              lockUntil: data.lockUntil
            });
            if (data.lockUntil) {
              startLockCountdown(data.lockUntil);
            }
            break;
          case 401:
            setError({
              field: 'general',
              message: 'Invalid email or password',
              remainingAttempts: data.remainingAttempts
            });
            break;
          case 404:
            setError({
              field: 'email',
              message: 'Account not found. Please check your email or sign up for a new account.'
            });
            break;
          case 400:
            setError({
              field: 'general',
              message: data.error || 'Invalid request. Please check your input.'
            });
            break;
          case 500:
            setError({
              field: 'general',
              message: data.message || 'Server error. Please try again later.'
            });
            break;
          default:
            setError({
              field: 'general',
              message: data.error || `Sign in failed (${response.status}). Please try again.`
            });
        }
        return;
      }
      // Store the temporary token and show OTP input
      setTempToken(data.token);
      setShowOtpInput(true);
      setIsSuccess(true);
    } catch (err) {
      setError({
        field: 'general',
        message: err instanceof Error ? err.message : "Network error occurred"
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Handle OTP submit (second step)
  const handleOtpSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!otp.trim()) {
      setError({
        field: 'otp',
        message: 'Please enter the verification code'
      });
      return;
    }
    try {
      setIsLoading(true);
      const response = await fetch(`${API_URL}/verify-token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          email: email.trim().toLowerCase(),
          token: otp
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        if (response.status === 423) {
          setError({
            field: 'otp',
            message: data.message || 'Account blocked due to too many failed attempts',
            isBlocked: true
          });
          // Reset the form after blocking
          setShowOtpInput(false);
          setOtp('');
          setVerificationAttempts(3);
        } else {
          setError({
            field: 'otp',
            message: data.error || 'Invalid verification code',
            remainingAttempts: data.remainingAttempts
          });
          if (data.remainingAttempts !== undefined) {
            setVerificationAttempts(data.remainingAttempts);
          }
        }
        return;
      }
      // Store the session token and user data
      localStorage.setItem('session', JSON.stringify({
        token: data.token,
        user: data.user,
        expiresAt: data.expiresAt
      }));
      // Navigate to dashboard only after successful verification
      navigate('/dashboard');
    } catch (err) {
      setError({
        field: 'general',
        message: err instanceof Error ? err.message : "Network error occurred"
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <div className="relative flex items-center justify-center">
              <Shield className="h-8 w-8 text-cyan-400" />
              <Lock className="h-4 w-4 text-white absolute" />
            </div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-cyan-200 bg-clip-text text-transparent">
              Patch Guardians
            </h1>
          </div>
          <p className="text-gray-400">Sign in to your account</p>
        </div>
        <form onSubmit={showOtpInput ? handleOtpSubmit : handleSubmit} className="space-y-6">
          {error && (
            <div className={`${
              error.isLocked || error.isBlocked ? 'bg-orange-500/10 border-orange-500/20' : 'bg-red-500/10 border-red-500/20'
            } border rounded-lg p-4 flex items-center gap-2 ${
              error.isLocked || error.isBlocked ? 'text-orange-400' : 'text-red-400'
            }`}>
              {error.isLocked || error.isBlocked ? (
                <Lock className="h-5 w-5 flex-shrink-0" />
              ) : (
                <AlertCircle className="h-5 w-5 flex-shrink-0" />
              )}
              <span>{formatErrorMessage(error)}</span>
            </div>
          )}
          {isSuccess && !showOtpInput && (
            <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4 flex items-center gap-2 text-green-400">
              <CheckCircle className="h-5 w-5" />
              <span>Verification code sent to your email!</span>
            </div>
          )}
          
          {!showOtpInput ? (
            <>
              <div className="space-y-2">
                <label htmlFor="signin-email" className="text-sm text-gray-300 block">
                  Email address
                </label>
                <div className="relative">
                  <Mail className="absolute left-3 top-2.5 h-5 w-5 text-gray-500" />
                  <input
                    id="signin-email"
                    name="email"
                    type="email"
                    placeholder="Enter your email"
                    value={email}
                    onChange={handleEmailChange}
                    className={`pl-10 bg-slate-800/50 border ${error?.field === 'email' ? 'border-red-500' : 'border-slate-700'} text-gray-100 placeholder:text-gray-500 w-full p-2 rounded-md`}
                    required
                    disabled={error?.isLocked || isLoading}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <label htmlFor="signin-password" className="text-sm text-gray-300 block">
                  Password
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-2.5 h-5 w-5 text-gray-500" />
                  <input
                    id="signin-password"
                    name="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="Enter your password"
                    value={password}
                    onChange={handlePasswordChange}
                    className={`pl-10 bg-slate-800/50 border ${error?.field === 'password' ? 'border-red-500' : 'border-slate-700'} text-gray-100 placeholder:text-gray-500 w-full p-2 rounded-md`}
                    required
                    disabled={error?.isLocked || isLoading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-2.5 text-gray-500 hover:text-gray-400"
                    disabled={error?.isLocked || isLoading}
                  >
                    {showPassword ? (
                      <EyeOff className="h-5 w-5" />
                    ) : (
                      <Eye className="h-5 w-5" />
                    )}
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="space-y-2">
              <label htmlFor="signin-otp" className="text-sm text-gray-300 block">
                Verification Code
              </label>
              <div className="relative">
                <input
                  id="signin-otp"
                  name="otp"
                  type="text"
                  placeholder="Enter verification code"
                  value={otp}
                  onChange={handleOtpChange}
                  className={`bg-slate-800/50 border ${error?.field === 'otp' ? 'border-red-500' : 'border-slate-700'} text-gray-100 placeholder:text-gray-500 w-full p-2 rounded-md`}
                  required
                  disabled={isLoading || error?.isBlocked}
                />
              </div>
              <p className="text-sm text-gray-400 mt-2">
                Enter the verification code sent to your email
                {verificationAttempts < 3 && (
                  <span className="text-orange-400 ml-1">
                    ({verificationAttempts} {verificationAttempts === 1 ? 'attempt' : 'attempts'} remaining)
                  </span>
                )}
              </p>
            </div>
          )}
          <button
            type="submit"
            className={`w-full bg-cyan-500 hover:bg-cyan-600 text-white font-medium py-2 px-4 rounded-md transition-colors ${
              isLoading || error?.isBlocked ? 'opacity-50 cursor-not-allowed' : ''
            }`}
            disabled={isLoading || error?.isLocked || error?.isBlocked}
          >
            {isLoading ? (
              <div className="flex items-center justify-center gap-2">
                <Loader2 className="h-5 w-5 animate-spin" />
                <span>Please wait...</span>
              </div>
            ) : showOtpInput ? (
              'Verify Code'
            ) : (
              'Sign In'
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

export default SignIn; 
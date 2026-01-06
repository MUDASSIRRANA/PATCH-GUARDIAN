import React, { useState, useEffect } from "react";
import { Eye, EyeOff, UserPlus, Mail, AlertCircle, CheckCircle, Loader2, X } from "lucide-react";

const API_URL = 'http://localhost:3001/api';

// Define error types for better error handling
type ErrorType = {
  field: 'email' | 'password' | 'name' | 'general' | null;
  message: string;
} | null;

const SignUp = () => {
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [agreedToTerms, setAgreedToTerms] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<ErrorType>(null);
  const [isSuccess, setIsSuccess] = useState(false);

  const [hasMinLength, setHasMinLength] = useState(false);
  const [hasUppercase, setHasUppercase] = useState(false);
  const [hasLowercase, setHasLowercase] = useState(false);
  const [hasSpecialChar, setHasSpecialChar] = useState(false);
  const [hasNumber, setHasNumber] = useState(false);

  const validatePassword = (value: string) => {
    setHasMinLength(value.length >= 8);
    setHasUppercase(/[A-Z]/.test(value));
    setHasLowercase(/[a-z]/.test(value));
    setHasSpecialChar(/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(value));
    setHasNumber(/[0-9]/.test(value));
  };

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newPassword = e.target.value;
    setPassword(newPassword);
    validatePassword(newPassword);
    // Clear password-related errors when user types
    if (error?.field === 'password') {
      setError(null);
    }
  };

  const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setEmail(e.target.value);
    // Clear email-related errors when user types
    if (error?.field === 'email') {
      setError(null);
    }
  };

  const handleNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setName(e.target.value);
    // Clear name-related errors when user types
    if (error?.field === 'name') {
      setError(null);
    }
  };

  useEffect(() => {
    validatePassword(password);
  }, []);

  const allRequirementsMet = hasMinLength && hasUppercase && hasLowercase && hasSpecialChar && hasNumber;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSuccess(false);

    // Validate name
    if (name.trim().length < 2) {
      setError({
        field: 'name',
        message: 'Name must be at least 2 characters long'
      });
      return;
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError({
        field: 'email',
        message: 'Please enter a valid email address'
      });
      return;
    }

    if (!allRequirementsMet) {
      const failedRequirements: string[] = [];
      if (!hasMinLength) failedRequirements.push("at least 8 characters long");
      if (!hasUppercase) failedRequirements.push("one uppercase letter");
      if (!hasLowercase) failedRequirements.push("one lowercase letter");
      if (!hasSpecialChar) failedRequirements.push("one special character");
      if (!hasNumber) failedRequirements.push("one number");
      
      setError({
        field: 'password',
        message: `Password must contain: ${failedRequirements.join(", ")}`
      });
      return;
    }

    if (!agreedToTerms) {
      setError({
        field: 'general',
        message: 'Please agree to the terms of service'
      });
      return;
    }

    try {
      setIsLoading(true);
      
      const response = await fetch(`${API_URL}/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name,
          email,
          password
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        // Handle specific error cases
        switch (response.status) {
          case 409:
            setError({
              field: 'email',
              message: 'This email is already registered'
            });
            break;
          case 400:
            if (data.field) {
              setError({
                field: data.field,
                message: data.error || 'Invalid input'
              });
            } else {
              setError({
                field: 'general',
                message: data.error || 'Invalid input'
              });
            }
            break;
          case 422:
            setError({
              field: 'password',
              message: 'Password does not meet security requirements'
            });
            break;
          default:
            setError({
              field: 'general',
              message: data.error || 'Registration failed'
            });
        }
        return;
      }

      setIsSuccess(true);
      setTimeout(() => {
        window.location.href = '/signin';
      }, 2000);

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
          <h1 className="text-2xl font-bold text-gray-100 mt-6 mb-2">Create an account</h1>
          <p className="text-gray-400">Start securing your applications today</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          {error && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 flex items-center gap-2 text-red-400">
              <AlertCircle className="h-5 w-5 flex-shrink-0" />
              <span>{error.message}</span>
            </div>
          )}

          {isSuccess && (
            <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4 flex items-center gap-2 text-green-400">
              <CheckCircle className="h-5 w-5" />
              <span>Account created successfully! Redirecting to sign in...</span>
            </div>
          )}

          <div className="space-y-2">
            <label htmlFor="signup-name" className="text-sm text-gray-300 block">
              Full name
            </label>
            <div className="relative">
              <UserPlus className="absolute left-3 top-2.5 h-5 w-5 text-gray-500" />
              <input
                id="signup-name"
                name="name"
                type="text"
                placeholder="Enter your name"
                value={name}
                onChange={handleNameChange}
                className={`pl-10 bg-slate-800/50 border ${error?.field === 'name' ? 'border-red-500' : 'border-slate-700'} text-gray-100 placeholder:text-gray-500 w-full p-2 rounded-md`}
                required
              />
            </div>
          </div>

          <div className="space-y-2">
            <label htmlFor="signup-email" className="text-sm text-gray-300 block">
              Email address
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-2.5 h-5 w-5 text-gray-500" />
              <input
                id="signup-email"
                name="email"
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={handleEmailChange}
                className={`pl-10 bg-slate-800/50 border ${error?.field === 'email' ? 'border-red-500' : 'border-slate-700'} text-gray-100 placeholder:text-gray-500 w-full p-2 rounded-md`}
                required
              />
            </div>
          </div>

          <div className="space-y-2">
            <label htmlFor="signup-password" className="text-sm text-gray-300 block">
              Password
            </label>
            <div className="relative">
              <input
                id="signup-password"
                name="password"
                type={showPassword ? "text" : "password"}
                placeholder="Create a password"
                value={password}
                onChange={handlePasswordChange}
                className={`pr-10 bg-slate-800/50 border ${error?.field === 'password' ? 'border-red-500' : 'border-slate-700'} text-gray-100 placeholder:text-gray-500 w-full p-2 rounded-md`}
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-2.5 text-gray-500 hover:text-gray-300"
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? (
                  <EyeOff className="h-5 w-5" />
                ) : (
                  <Eye className="h-5 w-5" />
                )}
              </button>
            </div>

            <div className="mt-2 space-y-1 border border-slate-700 rounded-lg p-3 bg-slate-800/50">
              <div className={`flex items-center gap-2 text-sm ${hasMinLength ? 'text-green-400' : 'text-red-400'}`}>
                {hasMinLength ? <CheckCircle className="h-4 w-4" /> : <X className="h-4 w-4" />}
                <span>At least 8 characters long</span>
              </div>
              <div className={`flex items-center gap-2 text-sm ${hasUppercase ? 'text-green-400' : 'text-red-400'}`}>
                {hasUppercase ? <CheckCircle className="h-4 w-4" /> : <X className="h-4 w-4" />}
                <span>One uppercase letter (A-Z)</span>
              </div>
              <div className={`flex items-center gap-2 text-sm ${hasLowercase ? 'text-green-400' : 'text-red-400'}`}>
                {hasLowercase ? <CheckCircle className="h-4 w-4" /> : <X className="h-4 w-4" />}
                <span>One lowercase letter (a-z)</span>
              </div>
              <div className={`flex items-center gap-2 text-sm ${hasNumber ? 'text-green-400' : 'text-red-400'}`}>
                {hasNumber ? <CheckCircle className="h-4 w-4" /> : <X className="h-4 w-4" />}
                <span>One number (0-9)</span>
              </div>
              <div className={`flex items-center gap-2 text-sm ${hasSpecialChar ? 'text-green-400' : 'text-red-400'}`}>
                {hasSpecialChar ? <CheckCircle className="h-4 w-4" /> : <X className="h-4 w-4" />}
                <span>One special character (!@#$%^&*()_+-=[]{}|;:,.&lt;&gt;?)</span>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <input
              id="signup-terms"
              type="checkbox"
              checked={agreedToTerms}
              onChange={(e) => setAgreedToTerms(e.target.checked)}
              className={`rounded border-gray-600 bg-slate-800/50 text-cyan-600 ${error?.field === 'general' ? 'border-red-500' : ''}`}
            />
            <label htmlFor="signup-terms" className="text-gray-300 text-sm">
              I agree to the Terms of Service and Privacy Policy
            </label>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full bg-gradient-to-r from-cyan-600 to-blue-600 hover:opacity-90 text-white p-2 rounded-md flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Creating Account...
              </>
            ) : (
              <>
                <UserPlus className="h-4 w-4" />
                Create Account
              </>
            )}
          </button>
        </form>

        <div className="mt-6 text-center text-sm">
          <span className="text-gray-400">Already have an account? </span>
          <a href="/signin" className="text-cyan-400 hover:text-cyan-300 font-medium">
            Sign in
          </a>
        </div>
      </div>
    </div>
  );
};

export default SignUp;
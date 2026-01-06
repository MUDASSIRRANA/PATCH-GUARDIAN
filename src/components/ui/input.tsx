import React, { InputHTMLAttributes } from 'react';

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  className?: string;
}

export const Input: React.FC<InputProps> = ({ 
  className = '', 
  ...props 
}) => {
  return (
    <input
      className={`w-full px-3 py-2 rounded-lg border transition-colors ${className}`}
      {...props}
    />
  );
}; 
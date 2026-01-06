import React from 'react';
import { Shield } from 'lucide-react';

export const Logo = () => {
  return (
    <div className="flex items-center gap-2">
      <Shield className="h-8 w-8 text-cyan-500" />
      <span className="text-xl font-bold text-cyan-500">SecurePatcher</span>
    </div>
  );
}; 
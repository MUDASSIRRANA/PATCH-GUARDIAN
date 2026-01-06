import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, Home } from 'lucide-react';
import { Button } from '@/components/ui/button';

const NotFound = () => {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-b from-[#0f1729] to-[#0f1f3d] text-gray-100 p-4">
      <div className="relative mb-8">
        <div className="absolute inset-0 bg-cyan-500 rounded-full blur-xl opacity-20"></div>
        <Shield className="w-20 h-20 text-cyan-400 relative" />
      </div>
      
      <h1 className="text-6xl font-bold text-cyan-400 mb-4">404</h1>
      <h2 className="text-2xl font-semibold text-gray-200 mb-2">Page Not Found</h2>
      <p className="text-gray-400 mb-8 text-center max-w-md">
        The page you're looking for doesn't exist or has been moved.
      </p>
      
      <Link to="/dashboard">
        <Button className="bg-cyan-500 hover:bg-cyan-600 text-white">
          <Home className="w-4 h-4 mr-2" />
          Return to Dashboard
        </Button>
      </Link>
    </div>
  );
};

export default NotFound;

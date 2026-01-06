import React from 'react';
import { Code, ShieldCheck, FileText, Shield, Lock } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';

const DashboardSidebar = () => {
  const location = useLocation();

  const isActive = (path: string) => {
    return location.pathname.includes(`/dashboard${path}`);
  };

  return (
    <div className="w-64 bg-[#0f1729] text-gray-300 min-h-screen p-6 flex flex-col border-r border-cyan-500/10">
      <div className="mb-10">
        <Link to="/dashboard" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
          <div className="relative flex items-center justify-center">
            <Shield className="h-8 w-8 text-cyan-400" />
            <Lock className="h-4 w-4 text-white absolute" />
          </div>
          <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-cyan-200 bg-clip-text text-transparent">
            Patch Guardians
          </h1>
        </Link>
      </div>
      <nav className="flex flex-col gap-4">
        <Link 
          to="/dashboard/codeanalysis" 
          className={`group flex items-center gap-3 p-2 rounded-lg transition-all duration-200 relative
            ${isActive('/codeanalysis') 
              ? 'text-cyan-400 bg-cyan-500/10' 
              : 'text-gray-400 hover:text-cyan-400 hover:bg-cyan-500/5'}`}
        >
          {/* Hover effect background */}
          <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-cyan-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
          
          {/* Content */}
          <div className="relative flex items-center gap-3">
            <Code className="w-5 h-5" />
            <span className="font-medium">Code Analysis</span>
          </div>
          
          {/* Active indicator */}
          {isActive('/codeanalysis') && (
            <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-cyan-400 rounded-r-full"></div>
          )}
        </Link>

        <Link 
          to="/dashboard/patch-management" 
          className={`group flex items-center gap-3 p-2 rounded-lg transition-all duration-200 relative
            ${isActive('/patch-management') 
              ? 'text-cyan-400 bg-cyan-500/10' 
              : 'text-gray-400 hover:text-cyan-400 hover:bg-cyan-500/5'}`}
        >
          {/* Hover effect background */}
          <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-cyan-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
          
          {/* Content */}
          <div className="relative flex items-center gap-3">
            <ShieldCheck className="w-5 h-5" />
            <span className="font-medium">Patch Management</span>
          </div>
          
          {/* Active indicator */}
          {isActive('/patch-management') && (
            <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-cyan-400 rounded-r-full"></div>
          )}
        </Link>

        <Link 
          to="/dashboard/report" 
          className={`group flex items-center gap-3 p-2 rounded-lg transition-all duration-200 relative
            ${isActive('/report') 
              ? 'text-cyan-400 bg-cyan-500/10' 
              : 'text-gray-400 hover:text-cyan-400 hover:bg-cyan-500/5'}`}
        >
          {/* Hover effect background */}
          <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-cyan-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
          
          {/* Content */}
          <div className="relative flex items-center gap-3">
            <FileText className="w-5 h-5" />
            <span className="font-medium">Report</span>
          </div>
          
          {/* Active indicator */}
          {isActive('/report') && (
            <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-cyan-400 rounded-r-full"></div>
          )}
        </Link>
      </nav>
    </div>
  );
};

export default DashboardSidebar;


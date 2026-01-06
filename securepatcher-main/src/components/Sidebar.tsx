// components/Sidebar.tsx
import React from 'react';
import { Code, ShieldCheck, FileText } from 'lucide-react';
import Link from 'next/link';

const Sidebar = () => {
  return (
    <div className="w-64 bg-slate-900 text-gray-300 min-h-screen p-6 flex flex-col">
      <div className="mb-10">
        <h1 className="text-2xl font-bold text-white">Patch Guardians</h1>
      </div>
      <nav className="flex flex-col gap-4">
        <Link href="/code-analysis" className="flex items-center gap-3 hover:text-white transition-colors">
          <Code size={20} />
          <span>Code Analysis</span>
        </Link>
        <Link href="/patch-management" className="flex items-center gap-3 hover:text-white transition-colors">
          <ShieldCheck size={20} />
          <span>Patch Management</span>
        </Link>
        <Link href="/report" className="flex items-center gap-3 hover:text-white transition-colors">
          <FileText size={20} />
          <span>Report</span>
        </Link>
      </nav>
    </div>
  );
};

export default Sidebar;

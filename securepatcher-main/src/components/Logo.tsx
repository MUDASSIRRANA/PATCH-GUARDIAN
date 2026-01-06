
import { Shield, Lock } from "lucide-react";

export function Logo() {
  return (
    <div className="flex items-center gap-2">
      <div className="relative flex items-center justify-center">
        <Shield className="h-8 w-8 text-cyan-400" />
        <Lock className="h-4 w-4 text-white absolute" />
      </div>
      <span className="font-bold text-xl text-cyan-300">Patch Guardians</span>
    </div>
  );
}

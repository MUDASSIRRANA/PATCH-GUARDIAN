
/*import React, { useState } from 'react';
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Shield, Zap, Code, Puzzle, File, Globe, Search, Lightbulb, Plus, Mic, Settings, Send, Share2 } from "lucide-react";

type PatchItem = {
  id: string;
  name: string;
  status: 'pending' | 'applied' | 'failed';
  type: string;
  icon: React.ReactNode;
};

const patchData: PatchItem[] = [
  {
    id: "patch-001",
    name: "SQL Injection Patch",
    status: "applied",
    type: "Security",
    icon: <Shield className="h-4 w-4" />
  },
  {
    id: "patch-002",
    name: "Prompt Injection Fix",
    status: "pending",
    type: "LLM",
    icon: <Zap className="h-4 w-4" />
  },
  {
    id: "patch-003",
    name: "Context Leak Prevention",
    status: "applied",
    type: "LLM",
    icon: <Puzzle className="h-4 w-4" />
  },
  {
    id: "patch-004",
    name: "Model Hallucination Guard",
    status: "failed",
    type: "LLM",
    icon: <Code className="h-4 w-4" />
  },
];

const statusColors = {
  pending: {
    dot: "bg-yellow-500",
    text: "text-yellow-400"
  },
  applied: {
    dot: "bg-green-500",
    text: "text-green-400"
  },
  failed: {
    dot: "bg-red-500",
    text: "text-red-400"
  }
};

export function LLMPatchSection() {
  const [inputValue, setInputValue] = useState("");
  const [showPatchList, setShowPatchList] = useState(false);

  return (
    <Card className="p-6 bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700 shadow-lg h-full">
      <div className="flex justify-between items-center mb-6">
        <h3 className="font-semibold text-cyan-300 flex items-center">
          <Zap className="h-5 w-5 mr-2 text-cyan-300" /> 
          LLM Patches
        </h3>
        <Button 
          variant="outline" 
          size="sm" 
          className="bg-cyan-900/50 text-cyan-300 border-cyan-700 hover:bg-cyan-800/50"
          onClick={() => setShowPatchList(!showPatchList)}
        >
          {showPatchList ? (
            <>
              <Zap className="h-4 w-4 mr-2" />
              Chat Interface
            </>
          ) : (
            <>
              <File className="h-4 w-4 mr-2" />
              View Patches
            </>
          )}
        </Button>
      </div>
      
      {showPatchList ? (
        // Patch list view
        <div className="space-y-4">
          {patchData.map((patch) => (
            <div 
              key={patch.id}
              className="flex items-center justify-between p-3 bg-slate-800/50 border border-slate-700 rounded-lg hover:bg-slate-700/30 transition-colors"
            >
              <div className="flex items-center gap-3">
                <div className={`w-2 h-2 ${statusColors[patch.status].dot} rounded-full`} />
                <div className="flex flex-col">
                  <span className="text-gray-200">{patch.name}</span>
                  <div className="flex items-center gap-1">
                    <span className={`text-xs ${statusColors[patch.status].text} capitalize`}>
                      {patch.status}
                    </span>
                    <span className="text-xs text-gray-400">• {patch.type}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center text-cyan-400 bg-cyan-900/20 p-1.5 rounded-md">
                {patch.icon}
              </div>
            </div>
          ))}
        </div>
      ) : (
        // Chat interface view - redesigned to match the reference image
        <div className="flex flex-col h-full">
          <div className="flex-1 mb-10 flex items-center justify-center">
            <div className="text-center max-w-md mx-auto">
              <h2 className="text-2xl font-bold text-gray-200 mb-3">What can I help with?</h2>
              <p className="text-gray-400 text-sm">
                Ask about vulnerabilities, request patches, or get security recommendations
              </p>
            </div>
          </div>
          
          <div className="relative">
            <div className="rounded-xl border border-slate-700 bg-slate-800/70 overflow-hidden">
              <Input
                type="text"
                placeholder="Ask anything"
                className="border-0 bg-transparent text-gray-200 py-6 px-4 focus-visible:ring-0 focus-visible:ring-offset-0"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
              />
              
              <div className="absolute right-3 top-1/2 -translate-y-1/2 flex space-x-1">
                <Button size="icon" variant="ghost" className="h-8 w-8 rounded-full text-gray-400 hover:text-cyan-400 hover:bg-cyan-900/20">
                  <Share2 className="h-5 w-5" />
                </Button>
                <Button size="icon" variant="ghost" className="h-8 w-8 rounded-full text-gray-400 hover:text-cyan-400 hover:bg-cyan-900/20">
                  <Send className="h-5 w-5" />
                </Button>
              </div>
            </div>
            
            <div className="mt-4 flex justify-center">
              <div className="flex space-x-2">
                <Button 
                  size="sm" 
                  variant="outline" 
                  className="rounded-full h-9 bg-slate-800/50 border-slate-700 text-gray-300 hover:bg-slate-700/50 hover:text-cyan-300"
                >
                  <Plus className="h-4 w-4 mr-1" />
                  <span>New</span>
                </Button>
                <Button 
                  size="sm" 
                  variant="outline" 
                  className="rounded-full h-9 bg-slate-800/50 border-slate-700 text-gray-300 hover:bg-slate-700/50 hover:text-cyan-300"
                >
                  <Globe className="h-4 w-4 mr-1" />
                  <span>Search</span>
                </Button>
                <Button 
                  size="sm" 
                  variant="outline" 
                  className="rounded-full h-9 bg-slate-800/50 border-slate-700 text-gray-300 hover:bg-slate-700/50 hover:text-cyan-300"
                >
                  <Lightbulb className="h-4 w-4 mr-1" />
                  <span>Reason</span>
                </Button>
              </div>
            </div>
            
            <div className="absolute left-3 bottom-[72px] text-xs text-gray-400">
              10000 chars
            </div>
          </div>
        </div>
      )}
      
      <div className="mt-5 pt-4 border-t border-slate-700">
        <Button 
          variant="ghost" 
          size="sm" 
          className="w-full text-cyan-300 hover:bg-cyan-900/20 hover:text-cyan-200"
        >
          {showPatchList ? "View All Patches" : "Create New Patch"}
        </Button>
      </div>
    </Card>
  );
}*/

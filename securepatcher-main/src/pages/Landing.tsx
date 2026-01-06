import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Logo } from "@/components/Logo";
import { ChevronRight, LogIn, UserPlus, Menu, X } from "lucide-react";

const Landing = () => {
  const navigate = useNavigate();
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 10) {
        setIsScrolled(true);
      } else {
        setIsScrolled(false);
      }
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollTo = (id: string) => {
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({
        behavior: "smooth",
      });
    }
    setMobileMenuOpen(false);
  };

  const toggleMobileMenu = () => {
    setMobileMenuOpen(!mobileMenuOpen);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-gray-100">
      {/* Navigation */}
      <header
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          isScrolled
            ? "bg-slate-900/80 backdrop-blur-md shadow-md"
            : "bg-transparent"
        }`}
      >
        <nav className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center">
            <Logo />
          </div>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-6">
            <button 
              onClick={() => scrollTo("features")} 
              className="text-gray-300 hover:text-cyan-300 transition-colors"
            >
              Features
            </button>
            <button 
              onClick={() => scrollTo("security")} 
              className="text-gray-300 hover:text-cyan-300 transition-colors"
            >
              Security
            </button>
            <button 
              onClick={() => scrollTo("about")} 
              className="text-gray-300 hover:text-cyan-300 transition-colors"
            >
              About
            </button>

            <div className="flex items-center space-x-3 ml-6">
              <Button 
                variant="outline" 
                onClick={() => navigate("/signin")}
                className="border-cyan-700 bg-transparent text-cyan-300 hover:bg-cyan-900/20"
              >
                <LogIn className="mr-2 h-4 w-4" />
                Sign In
              </Button>
              <Button 
                onClick={() => navigate("/signup")}
                className="bg-cyan-600 hover:bg-cyan-700 text-white"
              >
                <UserPlus className="mr-2 h-4 w-4" />
                Sign Up
              </Button>
            </div>
          </div>

          {/* Mobile Navigation Toggle Button */}
          <div className="md:hidden">
            <Button 
              variant="ghost" 
              size="icon" 
              onClick={toggleMobileMenu}
              className="text-gray-300"
            >
              {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
            </Button>
          </div>
        </nav>

        {/* Mobile Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden absolute top-full left-0 right-0 bg-slate-900 shadow-lg animate-fade-in">
            <div className="flex flex-col p-4 space-y-4">
              <button 
                onClick={() => scrollTo("features")} 
                className="text-left p-2 text-gray-300 hover:text-cyan-300 transition-colors"
              >
                Features
              </button>
              <button 
                onClick={() => scrollTo("security")} 
                className="text-left p-2 text-gray-300 hover:text-cyan-300 transition-colors"
              >
                Security
              </button>
              <button 
                onClick={() => scrollTo("about")} 
                className="text-left p-2 text-gray-300 hover:text-cyan-300 transition-colors"
              >
                About
              </button>
              <div className="flex flex-col space-y-3 pt-2">
                <Button 
                  variant="outline" 
                  onClick={() => navigate("/signin")}
                  className="border-cyan-700 bg-transparent text-cyan-300 hover:bg-cyan-900/20 w-full"
                >
                  <LogIn className="mr-2 h-4 w-4" />
                  Sign In
                </Button>
                <Button 
                  onClick={() => navigate("/signup")}
                  className="bg-cyan-600 hover:bg-cyan-700 text-white w-full"
                >
                  <UserPlus className="mr-2 h-4 w-4" />
                  Sign Up
                </Button>
              </div>
            </div>
          </div>
        )}
      </header>

      {/* Hero Section */}
      <section className="pt-32 pb-20 md:pt-48 md:pb-32 px-4">
        <div className="container mx-auto max-w-6xl">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-10 items-center">
            <div className="space-y-6">
              <div className="inline-block px-4 py-1.5 rounded-full bg-gradient-to-r from-cyan-900/50 to-cyan-700/30 border border-cyan-700/50 text-cyan-300 text-sm font-medium">
                Secure Your Code
              </div>
              <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold leading-tight">
                Protect Your Systems with <span className="text-gradient bg-gradient-to-r from-cyan-400 to-blue-500">Patch Guardian</span>
              </h1>
              <p className="text-lg md:text-xl text-gray-300 max-w-lg">
                Advanced Vulnerability Assessment and automated patching for modern applications. Detect vulnerabilities before they become threats.
              </p>
              <div className="flex flex-col sm:flex-row gap-4 pt-4">
                <Button 
                  size="lg" 
                  className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:opacity-90 text-white shadow-lg"
                  onClick={() => navigate("/signup")}
                >
                  Get Started
                  <ChevronRight className="ml-2 h-5 w-5" />
                </Button>
                <Button 
                  size="lg" 
                 
                  className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:opacity-90 text-white shadow-lg"
                  onClick={() => navigate("/dashboard")}
                >
                  View Demo
                </Button>
              </div>
            </div>
            <div className="relative">
              <div className="absolute -z-10 w-[300px] h-[300px] md:w-[500px] md:h-[500px] rounded-full bg-cyan-700/20 blur-[100px]"></div>
              <div className="relative bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700/50 rounded-xl p-4 shadow-xl">
                <div className="aspect-video overflow-hidden rounded-lg">
                  <div className="h-full w-full bg-gradient-to-br from-slate-700/50 to-cyan-900/30 rounded-lg p-8 flex items-center justify-center">
                    <div className="text-center">
                      <div className="flex justify-center mb-4">
                        <div className="bg-cyan-600/20 p-3 rounded-full">
                          <div className="bg-cyan-600/40 p-3 rounded-full">
                            <div className="bg-cyan-400 p-2 rounded-full">
                              <div className="h-8 w-8 text-slate-900 flex items-center justify-center">
                                <svg 
                                  xmlns="http://www.w3.org/2000/svg" 
                                  viewBox="0 0 24 24" 
                                  fill="none" 
                                  stroke="currentColor" 
                                  strokeWidth="2" 
                                  strokeLinecap="round" 
                                  strokeLinejoin="round"
                                >
                                  <circle cx="12" cy="12" r="9" />
                                  <path d="m12 8-4 4 4 4" />
                                  <path d="m16 12-4-4-4 4 4 4 4-4Z" />
                                </svg>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <h3 className="text-xl font-semibold text-cyan-300">Secure Integration</h3>
                      <p className="text-gray-400 mt-2">Vulnerability Detection and patching for Applications</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-24 px-4 bg-slate-900/50">
        <div className="container mx-auto max-w-6xl">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-6">Advanced Security Features</h2>
            <p className="text-gray-400 max-w-xl mx-auto">Our platform provides comprehensive protection against the latest security vulnerabilities and threats in Codes.</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {[
              {
                icon: (
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="h-8 w-8">
                    <path d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z" />
                    <path d="m9 12 2 2 4-4" />
                  </svg>
                ),
                title: "Vulnerability Detection",
                description: "Identify potential security risks in your AI models and applications before they can be exploited."
              },
              {
                icon: (
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="h-8 w-8">
                    <path d="M3.34 19a10 10 0 1 1 17.32 0" />
                    <path d="M13 19H7" />
                    <path d="M10 19v-7" />
                    <circle cx="10" cy="7" r="1" />
                  </svg>
                ),
                title: "Code Upload Panel",
                description: "Generate PDF reports summarizing scan results and patch actions taken."
              },
              {
                icon: (
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="h-8 w-8">
                    <path d="m8 3 4 8 5-5 5 15H2L8 3z" />
                  </svg>
                ),
                title: "Automated Patching",
                description: "Automatically fix vulnerabilities with our advanced AI-powered patching system."
              },
              {
                icon: (
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="h-8 w-8">
                    <circle cx="11" cy="11" r="8" />
                    <path d="m21 21-4.35-4.35" />
                  </svg>
                ),
                title: "Risk Assessment",
                description: "Comprehensive analysis of potential security threats and their impact on your systems."
              },
              {
                icon: (
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="h-8 w-8">
                    <rect width="18" height="18" x="3" y="3" rx="2" />
                    <path d="M7 7h10" />
                    <path d="M7 12h10" />
                    <path d="M7 17h10" />
                  </svg>
                ),
                title: "Reporting & Analytics",
                description: "Generate detailed reports for compliance and audit purposes with a single click."
              },
              {
                icon: (
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="h-8 w-8">
                    <path d="M3 11c0 2.9.87 5.4 2.65 7.4a1 1 0 0 0 1.38.1 6 6 0 0 1 8.03.87 1 1 0 0 0 1.38-.1A11.7 11.7 0 0 0 21 11a8 8 0 1 0-16 0v0Z" />
                    <path d="M7.5 11a2.5 2.5 0 0 1 5 0v0a2.5 2.5 0 0 1 5 0v0" />
                  </svg>
                ),
                title: "API Protection",
                description: "Secure your API endpoints from prompt injection and other common attack vectors."
              }
            ].map((feature, index) => (
              <div key={index} className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 hover:bg-slate-800 transition-all hover:-translate-y-1 hover:shadow-lg">
                <div className="bg-gradient-to-br from-cyan-900/30 to-cyan-700/20 p-3 rounded-xl w-16 h-16 flex items-center justify-center text-cyan-300 mb-5">
                  {feature.icon}
                </div>
                <h3 className="text-xl font-semibold mb-3">{feature.title}</h3>
                <p className="text-gray-400">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Security Section */}
      <section id="security" className="py-24 px-4">
        <div className="container mx-auto max-w-6xl">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-12 items-center">
            <div>
              <div className="bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700/50 rounded-xl p-6 shadow-xl">
                <div className="space-y-4">
                  <div className="flex items-center space-x-3 p-3 bg-slate-800/70 rounded-lg">
                    <div className="h-2 w-2 bg-green-500 rounded-full"></div>
                    <div className="text-sm text-gray-300">Threat detection active</div>
                  </div>
                  <div className="flex items-center space-x-3 p-3 bg-slate-800/70 rounded-lg">
                    <div className="h-2 w-2 bg-yellow-500 rounded-full"></div>
                    <div className="text-sm text-gray-300">3 potential vulnerabilities found</div>
                  </div>
                  <div className="flex items-center space-x-3 p-3 bg-slate-800/70 rounded-lg">
                    <div className="h-2 w-2 bg-cyan-500 rounded-full"></div>
                    <div className="text-sm text-gray-300">Patches ready for deployment</div>
                  </div>
                  <div className="mt-4 pt-4 border-t border-slate-700">
                    <Button className="w-full text-cyan-300 hover:bg-cyan-900/20 hover:text-cyan-200">
                      View Security Dashboard
                    </Button>
                  </div>
                </div>
              </div>
            </div>
            <div>
              <h2 className="text-3xl md:text-4xl font-bold mb-6">Enterprise-Grade Security</h2>
              <p className="text-gray-300 mb-6">
                Patch Guardians provides comprehensive protection for systems, safeguarding against both traditional attacks and emerging threats specific to coding and software.
              </p>
              <ul className="space-y-4">
                {[
                  "Protect against prompt injection, memory leakage and API misconfigrations",
                  "Performing Vulnerability assesment through Static & Dynamic analysis ",
                  "Identify insecure libraries, functions, and outdated dependencies",
                  "Validate patch effectiveness through integrated re-scanning",
                  "Specifically tailored for detecting security flaws in C++ codebases used in critical systems"
                ].map((item, index) => (
                  <li key={index} className="flex items-start">
                    <svg 
                      xmlns="http://www.w3.org/2000/svg" 
                      className="h-6 w-6 text-cyan-400 mr-2 flex-shrink-0 mt-0.5" 
                      fill="none" 
                      viewBox="0 0 24 24" 
                      stroke="currentColor"
                    >
                      <path 
                        strokeLinecap="round" 
                        strokeLinejoin="round" 
                        strokeWidth="2" 
                        d="M5 13l4 4L19 7" 
                      />
                    </svg>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
              <Button 
                className="mt-8 bg-gradient-to-r from-cyan-600 to-blue-600 hover:opacity-90 text-white"
                onClick={() => navigate("/signup")}
              >
                Get Protected Now
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* About Section */}
      <section id="about" className="py-24 px-4 bg-slate-900/50">
        <div className="container mx-auto max-w-6xl">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-6">About Patch Guardian</h2>
            <p className="text-gray-400 max-w-xl mx-auto">
              We're a team of security experts dedicated to protecting the code applications ans ensure secure software development.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              {
                number: "500+",
                label: "Vulnerabilities Patched",
                description: "Our system has identified and fixed hundreds of critical security issues."
              },
              {
                number: "99.9%",
                label: "Detection Rate",
                description: "Industry-leading threat detection with near-perfect accuracy."
              },
              {
                number: "24/7",
                label: "Monitoring & Support",
                description: "Round-the-clock monitoring and expert assistance whenever you need it."
              }
            ].map((stat, index) => (
              <div key={index} className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-8 text-center">
                <div className="text-4xl md:text-5xl font-bold text-cyan-400 mb-2">{stat.number}</div>
                <div className="text-xl font-medium mb-4">{stat.label}</div>
                <p className="text-gray-400">{stat.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-24 px-4">
        <div className="container mx-auto max-w-4xl">
          <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-2xl p-8 md:p-12 border border-slate-700/50 relative overflow-hidden shadow-xl">
            <div className="absolute -right-20 -top-20 w-64 h-64 bg-cyan-600/20 rounded-full blur-3xl"></div>
            <div className="absolute -left-20 -bottom-20 w-64 h-64 bg-blue-600/20 rounded-full blur-3xl"></div>
            <div className="relative z-10 text-center">
              <h2 className="text-3xl md:text-4xl font-bold mb-6">Ready to secure your applications?</h2>
              <p className="text-xl text-gray-300 mb-8 max-w-2xl mx-auto">
                Join hundreds of companies protecting their systems with Patch Guardians's advanced security platform.
              </p>
              <div className="flex flex-col sm:flex-row justify-center gap-4">
                <Button 
                  size="lg" 
                  className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:opacity-90 text-white shadow-lg"
                  onClick={() => navigate("/signup")}
                >
                  Get Started Free
                  <ChevronRight className="ml-2 h-5 w-5" />
                </Button>
               
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-slate-900 border-t border-slate-800 py-10 px-4">
        <div className="container mx-auto max-w-6xl">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-8">
            <div>
              <h3 className="font-semibold text-lg mb-4">Product</h3>
              <ul className="space-y-2">
                <li><a href="#" className="text-gray-400 hover:text-cyan-300 transition-colors">Features</a></li>
                <li><a href="#" className="text-gray-400 hover:text-cyan-300 transition-colors">Pricing</a></li>
                <li><a href="#" className="text-gray-400 hover:text-cyan-300 transition-colors">Integrations</a></li>
              </ul>
            </div>
            <div>
              <h3 className="font-semibold text-lg mb-4">Resources</h3>
              <ul className="space-y-2">
                <li><a href="#" className="text-gray-400 hover:text-cyan-300 transition-colors">Documentation</a></li>
                <li><a href="#" className="text-gray-400 hover:text-cyan-300 transition-colors">API</a></li>
                <li><a href="#" className="text-gray-400 hover:text-cyan-300 transition-colors">Guides</a></li>
              </ul>
            </div>
            <div>
              <h3 className="font-semibold text-lg mb-4">Company</h3>
              <ul className="space-y-2">
                <li><a href="#" className="text-gray-400 hover:text-cyan-300 transition-colors">About</a></li>
                <li><a href="#" className="text-gray-400 hover:text-cyan-300 transition-colors">Blog</a></li>
                <li><a href="#" className="text-gray-400 hover:text-cyan-300 transition-colors">Careers</a></li>
              </ul>
            </div>
            <div>
              <h3 className="font-semibold text-lg mb-4">Legal</h3>
              <ul className="space-y-2">
                <li><a href="#" className="text-gray-400 hover:text-cyan-300 transition-colors">Privacy</a></li>
                <li><a href="#" className="text-gray-400 hover:text-cyan-300 transition-colors">Terms</a></li>
                <li><a href="#" className="text-gray-400 hover:text-cyan-300 transition-colors">Cookie Policy</a></li>
              </ul>
            </div>
          </div>
          <div className="pt-8 border-t border-slate-800 flex flex-col md:flex-row justify-between items-center">
            <div className="mb-4 md:mb-0">
              <Logo />
              <p className="text-gray-500 text-sm mt-2">© 2025 Patch Guardian. All rights reserved.</p>
            </div>
            <div className="flex space-x-4">
              {["twitter", "linkedin", "github", "facebook"].map((social) => (
                <a 
                  key={social} 
                  href="#" 
                  className="bg-slate-800 hover:bg-slate-700 text-gray-400 hover:text-cyan-300 p-2 rounded-full transition-colors"
                >
                  <span className="sr-only">{social}</span>
                  <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                  </svg>
                </a>
              ))}
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
import { Github, Twitter, Mail } from "lucide-react";
import logo from "@/assets/logo.png";

const Footer = () => {
  return (
    <footer className="border-t border-border/50 py-12 bg-card/30">
      <div className="container mx-auto px-6">
        <div className="grid md:grid-cols-4 gap-8 mb-8">
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <img src={logo} alt="ArchGuardian Logo" className="h-6 w-6" />
              <span className="font-bold text-lg">ArchGuardian</span>
            </div>
            <p className="text-sm text-muted-foreground">
              AI-driven architecture analysis and remediation for modern development teams.
            </p>
          </div>
          
          <div>
            <h3 className="font-semibold mb-4">Product</h3>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li><a href="#features" className="hover:text-foreground transition-colors">Features</a></li>
              <li><a href="#architecture" className="hover:text-foreground transition-colors">Architecture</a></li>
              <li><a href="#capabilities" className="hover:text-foreground transition-colors">Capabilities</a></li>
              <li><a href="#" className="hover:text-foreground transition-colors">Pricing</a></li>
            </ul>
          </div>
          
          <div>
            <h3 className="font-semibold mb-4">Resources</h3>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li><a href="https://github.com/guiperry/archguardian/wiki" className="hover:text-foreground transition-colors">Documentation</a></li>
              <li><a href="https://github.com/guiperry/archguardian/wiki" className="hover:text-foreground transition-colors">API Reference</a></li>
              <li><a href="#" className="hover:text-foreground transition-colors">Examples</a></li>
              <li><a href="#" className="hover:text-foreground transition-colors">Blog</a></li>
            </ul>
          </div>
          
          <div>
            <h3 className="font-semibold mb-4">Connect</h3>
            <div className="flex gap-4">
              <a href="https://github.com/guiperry/archguardian/" className="w-10 h-10 rounded-lg bg-muted/50 flex items-center justify-center hover:bg-primary/20 transition-colors">
                <Github className="h-5 w-5" />
              </a>
              <a href="@G_Perry100" className="w-10 h-10 rounded-lg bg-muted/50 flex items-center justify-center hover:bg-primary/20 transition-colors">
                <Twitter className="h-5 w-5" />
              </a>
              <a href="#" className="w-10 h-10 rounded-lg bg-muted/50 flex items-center justify-center hover:bg-primary/20 transition-colors">
                <Mail className="h-5 w-5" />
              </a>
            </div>
          </div>
        </div>
        
        <div className="pt-8 border-t border-border/50 flex flex-col md:flex-row justify-between items-center gap-4">
          <p className="text-sm text-muted-foreground">
            © 2025 ArchGuardian. All rights reserved.
          </p>
          <div className="flex gap-6 text-sm text-muted-foreground">
            <a href="https://github.com/guiperry/archguardian/VULNERABILITY_DISCLOSURE_POLICY.md" className="hover:text-foreground transition-colors">Privacy</a>
            <a href="https://github.com/guiperry/archguardian/VULNERABILITY_DISCLOSURE_POLICY.md" className="hover:text-foreground transition-colors">Terms</a>
            <a href="https://github.com/guiperry/archguardian/VULNERABILITY_DISCLOSURE_POLICY.md" className="hover:text-foreground transition-colors">Security</a>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;

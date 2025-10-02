import { ArrowRight, Terminal } from "lucide-react";
import { Button } from "./ui/button";

const CTA = () => {
  return (
    <section className="py-24 relative overflow-hidden">
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-gradient-to-r from-primary/20 via-accent/20 to-primary/20 blur-3xl" />
      </div>
      
      <div className="container mx-auto px-6 relative z-10">
        <div className="max-w-4xl mx-auto">
          <div className="bg-card/50 backdrop-blur-sm border border-primary/30 rounded-3xl p-12 md:p-16 text-center relative overflow-hidden">
            <div className="absolute top-0 right-0 w-64 h-64 bg-primary/20 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2" />
            <div className="absolute bottom-0 left-0 w-64 h-64 bg-accent/20 rounded-full blur-3xl translate-y-1/2 -translate-x-1/2" />
            
            <div className="relative">
              <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6">
                <Terminal className="h-4 w-4 text-primary" />
                <span className="text-sm font-medium text-primary">Open Source</span>
              </div>
              
              <h2 className="text-4xl md:text-5xl font-bold mb-6">
                Ready to Guard Your Architecture?
              </h2>
              
              <p className="text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
                Start analyzing your codebase in minutes. Deep insights, automated fixes, and AI-powered remediation—all in one powerful tool.
              </p>
              
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <Button size="lg" className="bg-gradient-to-r from-primary to-accent hover:opacity-90 transition-opacity group">
                  Get Started Now
                  <ArrowRight className="ml-2 h-5 w-5 group-hover:translate-x-1 transition-transform" />
                </Button>
                <Button size="lg" variant="outline" className="border-primary/50 hover:bg-primary/10">
                  Read Documentation
                </Button>
              </div>
              
              <div className="mt-12 pt-8 border-t border-border/50">
                <p className="text-sm text-muted-foreground mb-4">Quick Install</p>
                <div className="bg-muted/30 rounded-lg p-4 font-mono text-sm inline-flex items-center gap-2">
                  <span className="text-accent">$</span>
                  <span className="text-foreground">go install github.com/archguardian/ag@latest</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default CTA;

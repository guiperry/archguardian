import { Code2, Database, GitBranch, Clock, Shield, Zap } from "lucide-react";

const capabilities = [
  {
    icon: Code2,
    title: "Multi-Language Support",
    description: "Go, Python, JavaScript/TypeScript, Java, C/C++, Rust, Ruby, PHP, C#, Swift, Kotlin, Scala"
  },
  {
    icon: Database,
    title: "Database ORM Detection",
    description: "Analyzes models, schemas, and relationships across your database layer"
  },
  {
    icon: GitBranch,
    title: "Safe Git Integration",
    description: "Auto-creates branches for fixes, never commits to main, detailed commit messages"
  },
  {
    icon: Clock,
    title: "Continuous Monitoring",
    description: "Configurable scan intervals for ongoing architecture health checks"
  },
  {
    icon: Shield,
    title: "Security First",
    description: "CVE detection, CVSS scoring, and vulnerability tracking across dependencies"
  },
  {
    icon: Zap,
    title: "Automated Updates",
    description: "Dependency managers: Go modules, NPM, pip with smart version management"
  }
];

const Capabilities = () => {
  return (
    <section id="capabilities" className="py-24 relative">
      <div className="absolute inset-0 bg-gradient-to-b from-background to-card/50" />
      
      <div className="container mx-auto px-6 relative z-10">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold mb-4">
            Built for Modern Development
          </h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Comprehensive capabilities that adapt to your entire tech stack
          </p>
        </div>
        
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-6xl mx-auto">
          {capabilities.map((capability, index) => (
            <div 
              key={index}
              className="p-6 rounded-xl border border-border/50 bg-card/30 backdrop-blur-sm hover:border-primary/30 hover:bg-card/50 transition-all duration-300 group"
            >
              <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                <capability.icon className="h-6 w-6 text-primary" />
              </div>
              <h3 className="text-lg font-semibold mb-2">{capability.title}</h3>
              <p className="text-sm text-muted-foreground">{capability.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Capabilities;

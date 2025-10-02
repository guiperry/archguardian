import { Cpu, Brain, Code } from "lucide-react";

const models = [
  {
    icon: Cpu,
    name: "Cerebras",
    purpose: "Fast Inference",
    description: "Lightning-fast code analysis and scanning for quick insights",
    color: "from-purple-500 to-pink-500"
  },
  {
    icon: Brain,
    name: "Gemini",
    purpose: "Deep Reasoning",
    description: "Advanced knowledge graph relationships and comprehensive risk analysis",
    color: "from-blue-500 to-cyan-500"
  },
  {
    icon: Code,
    name: "Claude/GPT/DeepSeek",
    purpose: "Code Remediation",
    description: "Configurable AI models for intelligent, context-aware code fixes",
    color: "from-orange-500 to-red-500"
  }
];

const ModelsArchitecture = () => {
  return (
    <section id="architecture" className="py-24 relative overflow-hidden">
      <div className="absolute inset-0">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-primary/10 rounded-full blur-3xl" />
      </div>
      
      <div className="container mx-auto px-6 relative z-10">
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-accent/10 border border-accent/20 mb-6">
            <span className="text-sm font-medium text-accent">Mixture-of-Models Architecture</span>
          </div>
          <h2 className="text-4xl md:text-5xl font-bold mb-4">
            Powered by Best-in-Class AI
          </h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Different AI models optimized for different tasks, working together seamlessly
          </p>
        </div>
        
        <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
          {models.map((model, index) => (
            <div 
              key={index}
              className="relative group"
            >
              <div className="absolute inset-0 bg-gradient-to-br opacity-10 group-hover:opacity-20 transition-opacity rounded-2xl blur-xl"
                style={{ backgroundImage: `linear-gradient(135deg, var(--tw-gradient-stops))` }}
              />
              
              <div className="relative p-8 rounded-2xl border border-border/50 bg-card/80 backdrop-blur-sm hover:border-primary/30 transition-all duration-300">
                <div className={`w-16 h-16 rounded-xl bg-gradient-to-br ${model.color} flex items-center justify-center mb-6 group-hover:scale-110 transition-transform`}>
                  <model.icon className="h-8 w-8 text-white" />
                </div>
                
                <h3 className="text-2xl font-bold mb-2">{model.name}</h3>
                <p className="text-sm text-accent font-medium mb-3">{model.purpose}</p>
                <p className="text-muted-foreground">{model.description}</p>
              </div>
            </div>
          ))}
        </div>
        
        <div className="mt-16 text-center">
          <div className="inline-flex items-center gap-2 px-6 py-3 rounded-full bg-muted/50 border border-border">
            <span className="text-sm text-muted-foreground">
              Each model excels at its specialized task, delivering optimal performance
            </span>
          </div>
        </div>
      </div>
    </section>
  );
};

export default ModelsArchitecture;

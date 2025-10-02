import { Network, AlertTriangle, Wrench } from "lucide-react";
import { Card } from "./ui/card";

const features = [
  {
    icon: Network,
    title: "System Understanding",
    subtitle: "Knowledge Graph",
    description: "Real-time mapping of code, APIs, databases, services, and data flows. Tracks dependencies and relationships across your entire stack with comprehensive JSON exports.",
    highlights: [
      "Automatic dependency mapping",
      "API & database tracking",
      "Visual graph exports",
      "Real-time updates"
    ]
  },
  {
    icon: AlertTriangle,
    title: "Risk Diagnosis",
    subtitle: "Comprehensive Analysis",
    description: "Identifies technical debt, security vulnerabilities (CVEs, CVSS scores), obsolete code, and dangerous dependencies with calculated risk scores.",
    highlights: [
      "CVE vulnerability scanning",
      "Technical debt detection",
      "Dead code identification",
      "Risk severity scoring"
    ]
  },
  {
    icon: Wrench,
    title: "Automated Remediation",
    subtitle: "AI-Powered Fixes",
    description: "AI-generated fixes for identified issues, automatic dependency updates, safe code removal, with separate Git branches and detailed commit messages.",
    highlights: [
      "AI-generated solutions",
      "Safe Git branching",
      "Automatic updates",
      "Detailed commit logs"
    ]
  }
];

const Features = () => {
  return (
    <section id="features" className="py-24 relative">
      <div className="absolute inset-0 bg-gradient-to-b from-card to-background" />
      
      <div className="container mx-auto px-6 relative z-10">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold mb-4">
            Core Capabilities
          </h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Three powerful features working together to give you complete control over your software architecture
          </p>
        </div>
        
        <div className="grid md:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <Card 
              key={index} 
              className="p-8 bg-card/50 backdrop-blur-sm border-primary/20 hover:border-primary/40 transition-all duration-300 hover:shadow-glow group"
            >
              <div className="mb-6">
                <div className="w-14 h-14 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                  <feature.icon className="h-7 w-7 text-white" />
                </div>
                <h3 className="text-2xl font-bold mb-1">{feature.title}</h3>
                <p className="text-sm text-accent font-medium">{feature.subtitle}</p>
              </div>
              
              <p className="text-muted-foreground mb-6">
                {feature.description}
              </p>
              
              <ul className="space-y-2">
                {feature.highlights.map((highlight, i) => (
                  <li key={i} className="flex items-center gap-2 text-sm">
                    <div className="w-1.5 h-1.5 rounded-full bg-primary" />
                    <span className="text-foreground/90">{highlight}</span>
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Features;

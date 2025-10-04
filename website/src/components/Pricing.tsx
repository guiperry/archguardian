import { Check, Github } from "lucide-react";
import { Card } from "./ui/card";
import { Button } from "./ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "./ui/tooltip";
import { useEffect } from "react";

declare global {
  interface Window {
    paypal?: {
      Buttons: (opts: unknown) => { render: (selector: string) => void };
    };
  }
}

const pricingPlans = [
  {
    title: "Open Source",
    subtitle: "Forever Free",
    description: "ArchGuardian CLI: The Developer's Command-Line Co-pilot\n\nGet started with ArchGuardian's core analysis and remediation engine, completely free and open-source. Built for developers who live in the terminal, the ArchGuardian CLI brings powerful, AI-driven architectural insights directly into your local development workflow.\n\nAnalyze your repositories, identify security risks, and generate code fixes without your source code ever leaving your machine. It's the perfect tool for individual developers, security researchers, and small teams looking to adopt a security-first mindset from the ground up.",
    features: [
      { title: "Comprehensive Local Analysis", description: "Run deep scans on any local or public Git repository to map dependencies, identify vulnerabilities, and detect technical debt." },
      { title: "AI-Powered Remediation", description: "Generate intelligent code fixes and dependency updates for issues found during analysis." },
      { title: "Bring Your Own AI Keys", description: "Integrate with your own API keys for Gemini, Claude, Cerebras, and other supported models, giving you full control over usage and costs." },
      { title: "Local-First Security", description: "Your code is analyzed on your machine. Nothing is sent to a third-party server, ensuring maximum privacy and security." },
      { title: "Git Integration", description: "Automatically creates new branches for proposed fixes with detailed, AI-generated commit messages." },
      { title: "Community Support", description: "Get help and contribute to the project via our GitHub repository and community channels." }
    ],
    button: {
      type: "link",
      text: "Get Started on GitHub",
      href: "https://github.com/guiperry/archguardian",
      icon: Github
    }
  },
  {
    title: "Cloud-Hosting",
    subtitle: "$5.99 Monthly",
    description: "ArchGuardian Cloud: Your Architecture Co-pilot, Fully Managed.\n\nMove beyond the command line and bring the full power of ArchGuardian to your entire team with our fully-managed cloud platform. We handle the infrastructure, AI model orchestration, and data visualization, so you can focus exclusively on building secure, robust, and maintainable software.\n\nArchGuardian Cloud is the definitive solution for development teams, security professionals, and enterprise architects who need deep, collaborative insights and a seamless, \"zero-config\" experience.",
    features: [
      { title: "Centralized Web Dashboard", description: "Connect your repositories and get a holistic view of your entire software ecosystem. Track architectural health, security posture, and technical debt across all your projects from a single, intuitive interface." },
      { title: "No AI Configuration Needed", description: "Get immediate access to our sophisticated Mixture-of-Models architecture—including Gemini, Cerebras, and Claude—without managing a single API key or token. We handle all the inference costs and complex orchestration for you." },
      { title: "Collaborative Workflows", description: "Assign issues, discuss remediation strategies, and track progress as a team. The cloud platform turns architectural analysis into a collaborative, actionable process, not just a developer-specific task." },
      { title: "Historical Analysis & Trend Reporting", description: "Don't just see a snapshot in time. ArchGuardian Cloud stores historical scan data, allowing you to visualize trends, measure the impact of your refactoring efforts, and prove a reduction in risk over time." },
      { title: "Automated CI/CD Integration", description: "Easily integrate ArchGuardian into your existing CI/CD pipelines with our secure webhooks and GitHub App. Enforce quality gates, block vulnerable dependencies, and get feedback directly in your pull requests." },
      { title: "Priority Support & Onboarding", description: "Our team will help you get set up and make the most of the platform. Cloud customers receive priority support for any questions or issues that arise." },
      { title: "Everything in the Open-Source CLI", description: "" },
      { title: "Unlimited private repository analysis", description: "" },
      { title: "User and team management", description: "" },
      { title: "Advanced data visualization and knowledge graphs", description: "" },
      { title: "Enterprise-grade security and SSO (coming soon)", description: "" }
    ],
    button: {
      type: "paypal",
      id: "paypal-button-container-P-9L031542LG006033FNDQA36Q",
      script: `<script src="https://www.paypal.com/sdk/js?client-id=AdPGnU51COkasse7mk00arRysO8TpSeEDdeP48XAfvLvtFfkVb9Ehf2v2VpElGJBV6GvXMHneTxNO6nA&vault=true&intent=subscription" data-sdk-integration-source="button-factory"></script>
<script>
  paypal.Buttons({
      style: {
          shape: 'rect',
          color: 'blue',
          layout: 'vertical',
          label: 'subscribe'
      },
      createSubscription: function(data, actions) {
        return actions.subscription.create({
          plan_id: 'P-9L031542LG006033FNDQA36Q',
          quantity: 1
        });
      },
      onApprove: function(data, actions) {
        alert(data.subscriptionID);
      }
  }).render('#paypal-button-container-P-9L031542LG006033FNDQA36Q');
</script>`
    }
  },
  {
    title: "ArchGuardian Enterprise",
    subtitle: "Contact for Pricing",
    description: "ArchGuardian Enterprise: Mission-Control for Your Software Ecosystem\n\nFor organizations that require the highest level of security, support, and integration, ArchGuardian Enterprise provides a complete, white-glove solution. It includes all the collaborative power of ArchGuardian Cloud, enhanced with dedicated support and enterprise-grade features to ensure your mission-critical applications are secure, compliant, and built to last.\n\nThis plan is designed for large development teams and enterprises that need to enforce architectural standards, manage risk at scale, and receive expert guidance on demand.",
    features: [
      { title: "Everything in ArchGuardian Cloud", description: "" },
      { title: "Dedicated Live Support", description: "Get real-time access to our senior engineers via dedicated chat channels (like Slack or Teams) and scheduled video calls for immediate assistance with complex issues." },
      { title: "Priority Onboarding & Team Training", description: "We provide personalized onboarding sessions and comprehensive training for your entire engineering organization to ensure rapid adoption and maximum value." },
      { title: "Custom Integration Engineering", description: "Our team will work with you to build bespoke integrations for your unique CI/CD pipelines, internal dashboards, and proprietary development tools." },
      { title: "Enterprise-Grade Security & Compliance", description: "" },
      { title: "Single Sign-On (SSO) with your identity provider (Okta, Azure AD, etc.)", description: "" },
      { title: "Detailed audit logs for security and compliance reviews", description: "" },
      { title: "Advanced Role-Based Access Control (RBAC) to manage permissions across your organization", description: "" },
      { title: "Guaranteed SLAs", description: "Benefit from a Service Level Agreement that guarantees uptime, support response times, and performance." },
      { title: "Private Model Hosting (Optional)", description: "For organizations with strict data residency or privacy requirements, we offer the option to deploy and run the AI models within your own cloud environment." }
    ],
    button: {
      type: "calendly-inline",
      url: "https://calendly.com/gizmorattler/30min",
      style: { minWidth: 320, height: 630 }
    }
  }
];

const Pricing = () => {
  useEffect(() => {
    // Load PayPal script for Cloud hosting (Enterprise PayPal intentionally not used here)
    const cloudScript = document.createElement('script');
    cloudScript.src = "https://www.paypal.com/sdk/js?client-id=AdPGnU51COkasse7mk00arRysO8TpSeEDdeP48XAfvLvtFfkVb9Ehf2v2VpElGJBV6GvXMHneTxNO6nA&vault=true&intent=subscription";
    cloudScript.setAttribute('data-sdk-integration-source', 'button-factory');
    document.head.appendChild(cloudScript);

    // Conditionally load Calendly widget script and stylesheet if any plan uses calendly-inline
    const hasCalendly = pricingPlans.some(p => {
      const b = (p as Record<string, unknown>).button as Record<string, unknown> | undefined;
      return b && b.type === 'calendly-inline';
    });
    let calendlyScript: HTMLScriptElement | null = null;
    let calendlyCss: HTMLLinkElement | null = null;
    if (hasCalendly) {
      calendlyCss = document.createElement('link');
      calendlyCss.rel = 'stylesheet';
      calendlyCss.href = 'https://assets.calendly.com/assets/external/widget.css';
      document.head.appendChild(calendlyCss);

      calendlyScript = document.createElement('script');
      calendlyScript.src = 'https://assets.calendly.com/assets/external/widget.js';
      calendlyScript.async = true;
      document.head.appendChild(calendlyScript);
    }

    cloudScript.onload = () => {
  if (window.paypal) {
        // Only render into containers that actually exist in the DOM.
        const cloudContainer = document.getElementById('paypal-button-container-P-9L031542LG006033FNDQA36Q');
        if (cloudContainer) {
          window.paypal.Buttons({
            style: {
              shape: 'rect',
              color: 'blue',
              layout: 'vertical',
              label: 'subscribe'
            },
            createSubscription: function(data, actions) {
              return actions.subscription.create({
                plan_id: 'P-9L031542LG006033FNDQA36Q',
                quantity: 1
              });
            },
            onApprove: function(data, actions) {
              alert(data.subscriptionID);
            }
          }).render('#paypal-button-container-P-9L031542LG006033FNDQA36Q');
        }

        const enterpriseContainer = document.getElementById('paypal-button-container-P-2X468481V7159314XNDQBCDQ');
        if (enterpriseContainer) {
          window.paypal.Buttons({
            style: {
              shape: 'rect',
              color: 'blue',
              layout: 'vertical',
              label: 'subscribe'
            },
            createSubscription: function(data, actions) {
              return actions.subscription.create({
                plan_id: 'P-2X468481V7159314XNDQBCDQ'
              });
            },
            onApprove: function(data, actions) {
              alert(data.subscriptionID);
            }
          }).render('#paypal-button-container-P-2X468481V7159314XNDQBCDQ');
        }
      }
    };

    return () => {
      if (cloudScript && document.head.contains(cloudScript)) document.head.removeChild(cloudScript);
      if (calendlyScript && document.head.contains(calendlyScript)) document.head.removeChild(calendlyScript);
      if (calendlyCss && document.head.contains(calendlyCss)) document.head.removeChild(calendlyCss);
    };
  }, []);

  return (
    <section id="pricing" className="py-24 relative">
      <div className="absolute inset-0 bg-gradient-to-b from-background to-card" />
      
      <div className="container mx-auto px-6 relative z-10">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold mb-4">
            Choose Your Plan
          </h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            From individual developers to enterprise teams, we have a plan that fits your needs
          </p>
        </div>
        
        <div className="grid md:grid-cols-3 gap-8">
          {pricingPlans.map((plan, index) => (
            <Card 
              key={index} 
              className="p-8 bg-card/50 backdrop-blur-sm border-primary/20 hover:border-primary/40 transition-all duration-300 hover:shadow-glow group"
            >
              <div className="mb-6">
                <h3 className="text-2xl font-bold mb-1">{plan.title}</h3>
                <p className="text-sm text-accent font-medium">{plan.subtitle}</p>
              </div>
              
              <p className="text-muted-foreground mb-6 whitespace-pre-line">
                {plan.description}
              </p>
              
              <TooltipProvider>
                <ul className="space-y-2 mb-8">
                  {plan.features.map((feature, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm">
                      <Check className="h-4 w-4 text-primary mt-0.5 flex-shrink-0" />
                      {feature.description ? (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="text-foreground/90 cursor-help">{feature.title}</span>
                          </TooltipTrigger>
                          <TooltipContent className="max-w-xs">
                            <p>{feature.description}</p>
                          </TooltipContent>
                        </Tooltip>
                      ) : (
                        <span className="text-foreground/90">{feature.title}</span>
                      )}
                    </li>
                  ))}
                </ul>
              </TooltipProvider>
              
              <div className="mt-auto">
                {plan.button.type === "link" ? (
                  <Button asChild className="w-full bg-gradient-to-r from-primary to-accent hover:opacity-90 transition-opacity group">
                    <a href={plan.button.href} target="_blank" rel="noopener noreferrer">
                      <plan.button.icon className="mr-2 h-4 w-4" />
                      {plan.button.text}
                    </a>
                  </Button>
                ) : plan.button.type === 'calendly-inline' ? (
                  <div className="w-full">
                    <div
                      className="calendly-inline-widget"
                      data-url={plan.button.url}
                      style={plan.button.style as React.CSSProperties}
                    />
                  </div>
                ) : (
                  <div id={plan.button.id} className="w-full"></div>
                )}
              </div>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Pricing;

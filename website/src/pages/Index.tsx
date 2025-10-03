import Navbar from "@/components/Navbar";
import Hero from "@/components/Hero";
import Features from "@/components/Features";
import ModelsArchitecture from "@/components/ModelsArchitecture";
import Capabilities from "@/components/Capabilities";
import Pricing from "@/components/Pricing";
import CTA from "@/components/CTA";
import Footer from "@/components/Footer";

const Index = () => {
  return (
    <div className="min-h-screen">
      <Navbar />
      <Hero />
      <Features />
      <ModelsArchitecture />
      <Capabilities />
      <Pricing />
      <CTA />
      <Footer />
    </div>
  );
};

export default Index;

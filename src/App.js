import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import './App.css';
import FashionPage from './pages/FashionPage';
import TechPage from './pages/TechPage';
import HRPage from './pages/HRPage';
import SaaSPage from './pages/SaaSPage';
import EcommercePage from './pages/EcommercePage';

const industries = [
  { name: 'Candles', external: true, url: 'https://www.dazzlo.co.in', video: '/assets/medias/candles.mp4' },
  { name: 'Fashion', path: '/fashion', video: '/assets/medias/fashion.mp4' },
  { name: 'Tech', path: '/tech', video: '/assets/medias/tech.mp4' },
  { name: 'HR', path: '/hr', video: '/assets/medias/hr.mp4' },
  { name: 'SaaS', path: '/saas', video: '/assets/medias/saas.mp4' },
  { name: 'E-commerce', path: '/ecommerce', video: '/assets/medias/ecommerce.mp4' },
];

export default function App() {
  const [showPopup, setShowPopup] = useState(false);
  const [formData, setFormData] = useState({ name: '', email: '', description: '' });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    alert(`Thank you, ${formData.name}! We'll reach out to you soon.`);
    setShowPopup(false);
    setFormData({ name: '', email: '', description: '' });
  };

  return (
    <Router>
      <Routes>
        <Route
          path="/"
          element={
            <div className="relative min-h-screen font-sans overflow-hidden">
              {/* Background Video */}
              <video
                className="absolute top-0 left-0 w-full h-full object-cover"
                autoPlay
                loop
                muted
                playsInline
              >
                <source src="/assets/medias/background.mp4" type="video/mp4" />
                Your browser does not support the video tag.
              </video>

              {/* Overlay Content */}
              <div className="relative z-10 text-white">
                <header className="flex justify-between items-center p-6 sticky top-0 bg-black/40 backdrop-blur-md z-10 shadow-md">
                  <div className="flex items-center space-x-3">
                    <motion.img
                      whileHover={{ scale: 1.2, rotate: 10 }}
                      src="/assets/medias/Logo.png"
                      alt="Dazzlo Logo"
                      className="h-10 w-10 animate-pulse"
                    />
                    <h1 className="text-3xl font-bold tracking-wide gradient-text">Dazzlo Verse</h1>
                  </div>
                  <nav className="space-x-4 text-sm md:text-base">
                    <a href="#about" className="hover:underline">About</a>
                    <a href="#industries" className="hover:underline">Industries</a>
                    <a href="#contact" className="hover:underline">Contact</a>
                    <button onClick={() => setShowPopup(true)} className="hover:underline">Join Us</button>
                  </nav>
                </header>

                <section className="flex flex-col items-center justify-center text-center py-32 px-4">
                  <motion.h2
                    animate={{ y: [0, -20, 0], scale: [1, 1.1, 1] }}
                    transition={{ repeat: Infinity, repeatType: 'loop', duration: 1, ease: 'easeInOut' }}
                    className="text-5xl font-extrabold bg-gradient-to-r from-purple-400 via-pink-500 to-red-500 bg-clip-text text-transparent tracking-widest mb-6"
                  >
                    Welcome to the Dazzlo Multiverse
                  </motion.h2>
                  <p className="max-w-2xl text-lg opacity-90">
                    Explore the expanding empire of Dazzlo across industries — from candles to tech, fashion to SaaS, and beyond.
                  </p>
                </section>

                <section id="about" className="px-8 py-20 text-center">
                  <h3 className="text-4xl font-bold mb-6 text-pink-400">About Dazzlo Verse</h3>
                  <p className="max-w-3xl mx-auto text-lg mb-4 opacity-90 leading-relaxed">
                    Welcome to Dazzlo Verse — a bold multiverse of innovation, creativity, and impact. From luxury candles to cutting-edge tech, fashion, SaaS, HR, and e-commerce, we redefine industries and craft unforgettable experiences.
                  </p>
                </section>

                <section id="industries" className="px-8 py-20">
                  <h3 className="text-4xl font-bold mb-12 text-center tracking-widest">Industries We Touch</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                    {industries.map((item, idx) => (
                      <motion.div
                        key={idx}
                        whileHover={{ scale: 1.05, boxShadow: "0px 0px 20px rgba(255,255,255,0.5)" }}
                        className="relative rounded-xl overflow-hidden shadow-lg transform transition-transform cursor-pointer h-48"
                      >
                        {item.external ? (
                          <a href={item.url} target="_blank" rel="noopener noreferrer">
                            <video className="absolute inset-0 w-full h-full object-cover" autoPlay loop muted playsInline>
                              <source src={item.video} type="video/mp4" />
                            </video>
                            <div className="absolute inset-0 bg-black/40 flex flex-col items-center justify-center text-center p-4">
                              <h4 className="text-xl font-semibold mb-1 tracking-wide">{item.name}</h4>
                              <p className="text-xs opacity-90">Discover how Dazzlo shapes the {item.name} industry.</p>
                            </div>
                          </a>
                        ) : (
                          <Link to={item.path}>
                            <video className="absolute inset-0 w-full h-full object-cover" autoPlay loop muted playsInline>
                              <source src={item.video} type="video/mp4" />
                            </video>
                            <div className="absolute inset-0 bg-black/40 flex flex-col items-center justify-center text-center p-4">
                              <h4 className="text-xl font-semibold mb-1 tracking-wide">{item.name}</h4>
                              <p className="text-xs opacity-90">Discover how Dazzlo shapes the {item.name} industry.</p>
                            </div>
                          </Link>
                        )}
                      </motion.div>
                    ))}
                  </div>
                </section>

                <section id="contact" className="px-8 py-20">
                  <h3 className="text-3xl font-bold mb-8 text-center tracking-widest">Contact Us</h3>
                  <div className="max-w-md mx-auto text-center">
                    <p className="mb-4 text-sm opacity-90">Want to collaborate, partner, or invest in the future of Dazzlo Verse?</p>
                    <button onClick={() => setShowPopup(true)} className="px-4 py-2 bg-pink-600 rounded-full hover:bg-pink-700 transition text-sm">Join Us</button>
                  </div>
                </section>

                {showPopup && (
                  <div className="fixed inset-0 bg-black/80 flex justify-center items-center z-50">
                    <div className="bg-white text-black p-4 rounded-lg w-72 relative">
                      <button className="absolute top-2 right-4 text-xl" onClick={() => setShowPopup(false)}>&times;</button>
                      <h4 className="text-lg font-bold mb-3 text-center">Join Us Form</h4>
                      <form onSubmit={handleSubmit} className="flex flex-col space-y-2 text-sm">
                        <input type="text" name="name" value={formData.name} onChange={handleChange} placeholder="Your Name" className="border p-1 rounded" required />
                        <input type="email" name="email" value={formData.email} onChange={handleChange} placeholder="Your Email" className="border p-1 rounded" required />
                        <textarea name="description" value={formData.description} onChange={handleChange} placeholder="Why are you joining us?" className="border p-1 rounded" rows="3" required />
                        <button type="submit" className="bg-purple-600 text-white py-1 rounded hover:bg-purple-700 transition">Submit</button>
                      </form>
                    </div>
                  </div>
                )}

                <footer className="py-6 bg-black text-white text-xs">
                  <div className="max-w-5xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-4 px-4">
                    <div>
                      <h4 className="font-semibold mb-2">Quick Links</h4>
                      <ul className="space-y-1">
                        <li><Link to="/">Home</Link></li>
                        <li><a href="#about" className="hover:underline">About</a></li>
                        <li><a href="#industries" className="hover:underline">Industries</a></li>
                        <li><a href="#contact" className="hover:underline">Contact</a></li>
                      </ul>
                    </div>
                    <div>
                      <h4 className="font-semibold mb-2">More</h4>
                      <ul className="space-y-1">
                        <li><a href="/services" className="hover:underline">Services</a></li>
                        <li><a href="/policy" className="hover:underline">Policy</a></li>
                        <li><a href="https://instagram.com" target="_blank" rel="noopener noreferrer" className="hover:underline">Instagram</a></li>
                        <li><a href="https://linkedin.com" target="_blank" rel="noopener noreferrer" className="hover:underline">LinkedIn</a></li>
                      </ul>
                    </div>
                    <div className="flex items-center justify-center md:justify-end text-center">
                      &copy; {new Date().getFullYear()} Dazzlo Verse Pvt Ltd. All rights reserved.
                    </div>
                  </div>
                </footer>
              </div>
            </div>
          }
        />

        {/* Only keeping the other industry routes */}
        <Route path="/fashion" element={<FashionPage video="/assets/medias/fashion.mp4" />} />
        <Route path="/tech" element={<TechPage video="/assets/medias/tech.mp4" />} />
        <Route path="/hr" element={<HRPage video="/assets/medias/hr.mp4" />} />
        <Route path="/saas" element={<SaaSPage video="/assets/medias/saas.mp4" />} />
        <Route path="/ecommerce" element={<EcommercePage video="/assets/medias/ecommerce.mp4" />} />
      </Routes>
    </Router>
  );
}

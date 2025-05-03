// TechPage.js
import React from 'react';
export default function TechPage({ video }) {
  return (
    <div className="relative min-h-screen text-white">
      <video className="fixed top-0 left-0 w-full h-full object-cover z-[-1]" autoPlay loop muted playsInline>
        <source src={video} type="video/mp4" />
      </video>
      <div className="flex flex-col items-center justify-center min-h-screen p-10 text-center bg-black/40">
        <h1 className="text-5xl font-bold mb-4">Welcome to Dazzlo Tech</h1>
        <p className="max-w-2xl text-center mb-6">
          Explore innovations, smart solutions, and digital transformations shaping the future of technology.
        </p>
        <a href="/" className="mt-4 px-6 py-2 bg-green-600 rounded-full hover:bg-green-700 transition">
          Back to Home
        </a>
      </div>
    </div>
  );
}
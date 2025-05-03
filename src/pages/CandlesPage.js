// CandlesPage.js
import React from 'react';
export default function CandlesPage({ video }) {
  return (
    <div className="relative min-h-screen text-white">
      <video className="fixed top-0 left-0 w-full h-full object-cover z-[-1]" autoPlay loop muted playsInline>
        <source src={video} type="video/mp4" />
      </video>
      <div className="flex flex-col items-center justify-center min-h-screen p-10 text-center bg-black/40">
        <h1 className="text-5xl font-bold mb-4">Welcome to Dazzlo Candles</h1>
        <p className="max-w-2xl text-center mb-6">
          Light up your senses with our premium aromatic candle collection. Perfect for gifts, décor, and unforgettable moments.
        </p>
        <a href="/" className="mt-4 px-6 py-2 bg-yellow-600 rounded-full hover:bg-yellow-700 transition">
          Back to Home
        </a>
      </div>
    </div>
  );
}

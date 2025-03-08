<?php

namespace Utopia\Auth\Proofs;

use Utopia\Auth\Proof;

class Phrase extends Proof
{
    private array $adjectives = ['Abundant', 'Adaptable', 'Adventurous', 'Affectionate', 'Agile', 'Amiable', 'Amazing', 'Ambitious', 'Amicable', 'Amusing', 'Astonishing', 'Attentive', 'Authentic', 'Awesome', 'Balanced', 'Beautiful', 'Bold', 'Brave', 'Bright', 'Bubbly', 'Calm', 'Capable', 'Charismatic', 'Charming', 'Cheerful', 'Clever', 'Colorful', 'Compassionate', 'Confident', 'Cooperative', 'Courageous', 'Courteous', 'Creative', 'Curious', 'Dazzling', 'Dedicated', 'Delightful', 'Determined', 'Diligent', 'Dynamic', 'Easygoing', 'Effervescent', 'Efficient', 'Elegant', 'Empathetic', 'Energetic', 'Enthusiastic', 'Exuberant', 'Faithful', 'Fantastic', 'Fearless', 'Flexible', 'Friendly', 'Fun-loving', 'Generous', 'Gentle', 'Genuine', 'Graceful', 'Gracious', 'Happy', 'Hardworking', 'Harmonious', 'Helpful', 'Honest', 'Hopeful', 'Humble', 'Imaginative', 'Impressive', 'Incredible', 'Inspiring', 'Intelligent', 'Joyful', 'Kind', 'Knowledgeable', 'Lively', 'Lovable', 'Lovely', 'Loyal', 'Majestic', 'Magnificent', 'Mindful', 'Modest', 'Passionate', 'Patient', 'Peaceful', 'Perseverant', 'Playful', 'Polite', 'Positive', 'Powerful', 'Practical', 'Precious', 'Proactive', 'Productive', 'Punctual', 'Quick-witted', 'Radiant', 'Reliable', 'Resilient', 'Resourceful', 'Respectful', 'Responsible', 'Sensitive', 'Serene', 'Sincere', 'Skillful', 'Soothing', 'Spirited', 'Splendid', 'Steadfast', 'Strong', 'Supportive', 'Sweet', 'Talented', 'Thankful', 'Thoughtful', 'Thriving', 'Tranquil', 'Trustworthy', 'Upbeat', 'Versatile', 'Vibrant', 'Vigilant', 'Warmhearted', 'Welcoming', 'Wholesome', 'Witty', 'Wonderful', 'Zealous'];

    private array $nouns = ['apple', 'banana', 'cat', 'dog', 'elephant', 'fish', 'guitar', 'hat', 'ice cream', 'jacket', 'kangaroo', 'lemon', 'moon', 'notebook', 'orange', 'piano', 'quilt', 'rabbit', 'sun', 'tree', 'umbrella', 'violin', 'watermelon', 'xylophone', 'yogurt', 'zebra', 'airplane', 'ball', 'cloud', 'diamond', 'eagle', 'fire', 'giraffe', 'hammer', 'island', 'jellyfish', 'kiwi', 'lamp', 'mango', 'needle', 'ocean', 'pear', 'quasar', 'rose', 'star', 'turtle', 'unicorn', 'volcano', 'whale', 'xylograph', 'yarn', 'zephyr', 'ant', 'book', 'candle', 'door', 'envelope', 'feather', 'globe', 'harp', 'insect', 'jar', 'kite', 'lighthouse', 'magnet', 'necklace', 'owl', 'puzzle', 'queen', 'rainbow', 'sailboat', 'telescope', 'umbrella', 'vase', 'wallet', 'xylograph', 'yacht', 'zeppelin', 'accordion', 'brush', 'chocolate', 'dolphin', 'easel', 'fountain', 'globe', 'hairbrush', 'iceberg', 'jigsaw', 'kettle', 'leopard', 'marble', 'nutmeg', 'obstacle', 'penguin', 'quiver', 'raccoon', 'sphinx', 'trampoline', 'utensil', 'velvet', 'wagon', 'xerox', 'yodel', 'zipper'];

    /**
     * Constructor
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Generate a proof
     *
     * @return string
     */
    public function generate(): string
    {
        $adjective = $this->adjectives[array_rand($this->adjectives)];
        $noun = $this->nouns[array_rand($this->nouns)];

        return "{$adjective} {$noun}";
    }

    /**
     * Hash a proof
     *
     * @param  string  $proof
     * @return string
     */
    public function hash(string $proof): string
    {
        return $this->algorithm->hash($proof);
    }

    /**
     * Verify a proof
     *
     * @param  string  $proof
     * @param  string  $hash
     * @return bool
     */
    public function verify(string $proof, string $hash): bool
    {
        return $this->algorithm->verify($proof, $hash);
    }
}

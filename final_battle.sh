#!/bin/bash
cd /workspace

echo "🎯 METASPLOIT PYTHON MIGRATION: ROUNDS 3 & 4"
echo "=============================================="
echo "🔥 Ruby v Python: Round 4: FIGHT!"
echo "🐍 Only when done with round 3: kill ruby. Make it python. Be sneaky. Ride the snake."
echo ""

python3 execute_mission.py

echo ""
echo "🏁 MISSION STATUS CHECK..."
if [ $? -eq 0 ]; then
    echo "✅ SUCCESS: Ruby has been eliminated! Python dominates!"
    echo "🐍 The snake has won the battle!"
else
    echo "❌ FAILED: Ruby still lives to fight another day!"
fi
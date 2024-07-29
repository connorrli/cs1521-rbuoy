fizzBuzz n = case (n `mod` 3, n `mod` 5) of
  (0, 0) -> "fizz buzz!"
  (0, _) -> "fizz..."
  (_, 0) -> "buzz?"
  (_, _) -> show n

main = mapM_ (putStrLn . fizzBuzz) [1..]

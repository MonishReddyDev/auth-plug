import passport from "passport";
import {
  Strategy as GoogleStrategy,
  Profile,
  VerifyCallback,
} from "passport-google-oauth20";
import prisma from "./prisma";
import googleConfig from "./google";
import {
  Strategy as GitHubStrategy,
  Profile as GitHubProfile,
} from "passport-github2";
import githubConfig from "./github";

passport.use(
  new GoogleStrategy(
    googleConfig,
    async (
      accessToken: string,
      refreshToken: string,
      profile: Profile,
      done: VerifyCallback
    ) => {
      try {
        const email = profile.emails?.[0].value;
        if (!email) return done(null, false);

        // Check if user exists
        let user = await prisma.user.findUnique({ where: { email } });

        // If not, create a new user, mark as verified
        if (!user) {
          user = await prisma.user.create({
            data: {
              email,
              name: profile.displayName,
              isVerified: true,
              provider: "google",
              providerId: profile.id,
              password: "", // Google users may not have a password, so set as empty string or a random value
            },
          });
        }
        return done(null, user);
      } catch (error) {
        return done(error, undefined);
      }
    }
  )
);

passport.use(
  new GitHubStrategy(
    githubConfig,
    async (
      accessToken: string,
      refreshToken: string,
      profile: GitHubProfile,
      done: (error: any, user?: Express.User | false | null) => void
    ) => {
      try {
        const email =
          profile.emails?.[0]?.value || profile.username + "@github.com";
        let user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
          user = await prisma.user.create({
            data: {
              email,
              name: profile.displayName || profile.username,
              isVerified: true,
              provider: "github",
              providerId: profile.id,
              password: "",
              // add other fields as needed
            },
          });
        }

        return done(null, user);
      } catch (err) {
        return done(err, false);
      }
    }
  )
);

// (Optional) serialize/deserialize user for sessions
passport.serializeUser((user: any, done) => done(null, user.id));
passport.deserializeUser(async (id: string, done) => {
  const user = await prisma.user.findUnique({ where: { id } });
  done(null, user);
});

export default passport;
